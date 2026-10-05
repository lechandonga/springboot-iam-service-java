package com.github.lechandonga.springbootiamservicejava.iam.token;

import com.github.lechandonga.springbootiamservicejava.iam.config.IamProperties;
import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * 自包含签名访问令牌：base64url(payloadJson).base64url(hmacSha256(payload))。
 * 不依赖外部身份服务；payload 含签发时刻、过期时刻、账号安全版本与会话 id。
 */
@Component
public class TokenService {

    private static final Base64.Encoder URL_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DEC = Base64.getUrlDecoder();

    private final IamProperties properties;
    private final SecureRandom random = new SecureRandom();
    private final Clock clock = Clock.systemUTC();

    public TokenService(IamProperties properties) {
        this.properties = properties;
    }

    public record Payload(String sub, String sid, String jti, long ver, long iat, long exp) {
    }

    public AccessToken issueAccessToken(String username, String sessionId, long securityVersion) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(properties.getAccessTokenTtl());
        Payload payload = new Payload(username, sessionId, UUID.randomUUID().toString(), securityVersion,
                now.getEpochSecond(), expiresAt.getEpochSecond());
        String payloadJson = toJson(payload);
        String token = encodePayload(payloadJson) + "." + sign(payloadJson);
        return new AccessToken(token, username, sessionId, securityVersion, now, expiresAt);
    }

    /** 生成高熵一次性刷新令牌明文（仅本次返回给调用方）。 */
    public String generateRefreshTokenRaw() {
        byte[] bytes = new byte[48];
        random.nextBytes(bytes);
        return "rt_" + URL_ENC.encodeToString(bytes);
    }

    public Duration refreshTokenTtl() {
        return properties.getRefreshTokenTtl();
    }

    public Instant refreshTokenExpiry() {
        return clock.instant().plus(properties.getRefreshTokenTtl());
    }

    public Instant now() {
        return clock.instant();
    }

    public Payload verify(String token) {
        if (token == null || token.isBlank()) {
            throw new TokenException(ErrorCode.TOKEN_MISSING);
        }
        int dot = token.lastIndexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            throw new TokenException(ErrorCode.TOKEN_MALFORMED);
        }
        String payloadPart = token.substring(0, dot);
        String signaturePart = token.substring(dot + 1);
        String payloadJson;
        try {
            payloadJson = new String(URL_DEC.decode(payloadPart), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new TokenException(ErrorCode.TOKEN_MALFORMED);
        }
        byte[] signature;
        try {
            signature = URL_DEC.decode(signaturePart);
        } catch (IllegalArgumentException e) {
            throw new TokenException(ErrorCode.TOKEN_BAD_SIGNATURE);
        }
        byte[] expected = hmac(payloadJson);
        if (!constantTimeEquals(expected, signature)) {
            if (signature.length != expected.length) {
                // 签名字节长度都不对：伪造的签名
                throw new TokenException(ErrorCode.TOKEN_BAD_SIGNATURE);
            }
            // 长度正常但验签失败：payload 是可解析内容却与签名不符，按内容被篡改拒绝
            if (looksLikeJson(payloadJson)) {
                throw new TokenException(ErrorCode.TOKEN_TAMPERED);
            }
            throw new TokenException(ErrorCode.TOKEN_BAD_SIGNATURE);
        }
        Payload payload = fromJson(payloadJson);
        if (payload.sub() == null || payload.sid() == null || payload.jti() == null
                || payload.exp() <= 0) {
            throw new TokenException(ErrorCode.TOKEN_MALFORMED);
        }
        if (clock.instant().getEpochSecond() >= payload.exp()) {
            throw new TokenException(ErrorCode.TOKEN_EXPIRED);
        }
        return payload;
    }

    private boolean looksLikeJson(String value) {
        String trimmed = value.trim();
        return trimmed.startsWith("{") && trimmed.endsWith("}");
    }

    private String encodePayload(String json) {
        return URL_ENC.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private String sign(String payloadJson) {
        return URL_ENC.encodeToString(hmac(payloadJson));
    }

    private byte[] hmac(String payloadJson) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] keyBytes = properties.getTokenSigningKey().getBytes(StandardCharsets.UTF_8);
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            return mac.doFinal(payloadJson.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IamException(ErrorCode.INTERNAL_ERROR, "token signing unavailable");
        }
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /** 极简 JSON 序列化（payload 字段全部为安全字符：sid/sub 仅含字母数字-_）。 */
    private String toJson(Payload p) {
        return "{\"sub\":\"" + p.sub() + "\",\"sid\":\"" + p.sid() + "\",\"jti\":\"" + p.jti()
                + "\",\"ver\":" + p.ver()
                + ",\"iat\":" + p.iat() + ",\"exp\":" + p.exp() + "}";
    }

    private Payload fromJson(String json) {
        try {
            String sub = extractString(json, "sub");
            String sid = extractString(json, "sid");
            long ver = extractLong(json, "ver");
            long iat = extractLong(json, "iat");
            long exp = extractLong(json, "exp");
            String jti = extractString(json, "jti");
            return new Payload(sub, sid, jti, ver, iat, exp);
        } catch (RuntimeException e) {
            throw new TokenException(ErrorCode.TOKEN_MALFORMED);
        }
    }

    private String extractString(String json, String key) {
        String marker = "\"" + key + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) {
            return null;
        }
        start += marker.length();
        int end = json.indexOf('"', start);
        return end < 0 ? null : json.substring(start, end);
    }

    private long extractLong(String json, String key) {
        String marker = "\"" + key + "\":";
        int start = json.indexOf(marker);
        if (start < 0) {
            throw new IllegalArgumentException(key);
        }
        start += marker.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        return Long.parseLong(json.substring(start, end));
    }
}
