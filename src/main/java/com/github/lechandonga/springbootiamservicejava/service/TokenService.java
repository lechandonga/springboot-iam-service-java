package com.github.lechandonga.springbootiamservicejava.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lechandonga.springbootiamservicejava.config.IamProperties;
import com.github.lechandonga.springbootiamservicejava.domain.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.domain.IamException;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Compact HMAC-SHA256 signed tokens: base64url(payloadJson).base64url(signature).
 *
 * <p>Access tokens are short lived and statelessly verifiable; revocation is
 * enforced through their session chain. Refresh tokens are high-entropy opaque
 * strings (also signed), one-time-use; only a SHA-256 hash is stored.
 */
@Service
public class TokenService {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final IamProperties properties;
    private final ObjectMapper objectMapper;
    private final SecureRandom random = new SecureRandom();
    private final byte[] signingKey;
    private Clock clock = Clock.systemUTC();

    public TokenService(IamProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.signingKey = properties.getTokenSigningSecret().getBytes(StandardCharsets.UTF_8);
    }

    /** Test hook for exercising expiry handling deterministically. */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    public record IssuedToken(String raw, String jti, Instant expiresAt) {}

    public IssuedToken issueAccess(String username, String chainId) {
        return issue(TYPE_ACCESS, username, chainId, properties.getAccessTokenTtl());
    }

    public IssuedToken issueRefresh(String username, String chainId) {
        return issue(TYPE_REFRESH, username, chainId, properties.getRefreshTokenTtl());
    }

    private IssuedToken issue(String type, String username, String chainId, Duration ttl) {
        Instant now = Instant.now(clock);
        Instant expiresAt = now.plus(ttl);
        String jti = randomId();
        ObjectNode payload = objectMapper.createObjectNode()
                .put("ver", 1)
                .put("typ", type)
                .put("sub", username)
                .put("cid", chainId)
                .put("jti", jti)
                .put("iat", now.getEpochSecond())
                .put("exp", expiresAt.getEpochSecond());
        String payloadB64 = encodeUrl(toJson(payload).getBytes(StandardCharsets.UTF_8));
        String signatureB64 = sign(payloadB64);
        return new IssuedToken(payloadB64 + "." + signatureB64, jti, expiresAt);
    }

    /**
     * Verifies structure, signature and expiry. Type is checked separately by
     * the caller. Returns the parsed claims.
     */
    public JsonNode verify(String rawToken, String expectedType) {
        if (rawToken == null) {
            throw new IamException(ErrorCode.MISSING_TOKEN);
        }
        int dot = rawToken.lastIndexOf('.');
        if (dot <= 0 || dot == rawToken.length() - 1) {
            throw new IamException(ErrorCode.MALFORMED_TOKEN);
        }
        String payloadB64 = rawToken.substring(0, dot);
        String signatureB64 = rawToken.substring(dot + 1);

        byte[] expectedSignature = hmac(payloadB64);
        if (!constantTimeEquals(expectedSignature, decodeUrl(signatureB64))) {
            throw new IamException(ErrorCode.BAD_SIGNATURE);
        }

        JsonNode claims;
        try {
            claims = objectMapper.readTree(decodeUrl(payloadB64));
        } catch (Exception e) {
            throw new IamException(ErrorCode.MALFORMED_TOKEN);
        }
        if (!claims.has("typ") || !claims.has("sub") || !claims.has("cid") || !claims.has("exp")) {
            throw new IamException(ErrorCode.MALFORMED_TOKEN);
        }
        if (!expectedType.equals(claims.get("typ").asText())) {
            throw new IamException(ErrorCode.TOKEN_TYPE_MISMATCH);
        }
        Instant expiresAt = Instant.ofEpochSecond(claims.get("exp").asLong());
        if (!Instant.now(clock).isBefore(expiresAt)) {
            throw new IamException(ErrorCode.TOKEN_EXPIRED);
        }
        return claims;
    }

    /** One-way fingerprint of a token; this is all that is persisted server-side. */
    public String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("sha-256 unavailable", e);
        }
    }

    private String sign(String payloadB64) {
        return encodeUrl(hmac(payloadB64));
    }

    private byte[] hmac(String payloadB64) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(signingKey, HMAC_ALGORITHM));
            return mac.doFinal(payloadB64.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("hmac unavailable", e);
        }
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    private String randomId() {
        byte[] bytes = new byte[18];
        random.nextBytes(bytes);
        return encodeUrl(bytes);
    }

    private String toJson(Object node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String encodeUrl(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] decodeUrl(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
