package com.github.lechandonga.springbootiamservicejava.iam.security;

/** 请求级身份持有器，过滤器 set、控制器 get、请求结束后 clear。 */
public final class SecurityContext {

    private static final ThreadLocal<CurrentPrincipal> HOLDER = new ThreadLocal<>();

    private SecurityContext() {
    }

    public static void set(CurrentPrincipal principal) {
        HOLDER.set(principal);
    }

    public static CurrentPrincipal get() {
        return HOLDER.get();
    }

    public static CurrentPrincipal required() {
        CurrentPrincipal principal = HOLDER.get();
        if (principal == null) {
            throw new com.github.lechandonga.springbootiamservicejava.iam.error.IamException(
                    com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode.TOKEN_MISSING);
        }
        return principal;
    }

    public static void clear() {
        HOLDER.remove();
    }
}
