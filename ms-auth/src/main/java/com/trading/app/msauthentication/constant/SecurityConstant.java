package com.trading.app.msauthentication.constant;

public class SecurityConstant {
    public static final String SIGN_UP_URL = "/users/record";
    public static final String KEY = "q3t6w9z$C&F)J@NcQfTjWnZr4u7x!A%D*G-KaPdSgUkXp2s5v8y/B?E(H+MbQeTh";
    public static final String HEADER_NAME = "Authorization";
    public static final Long EXPIRATION_TIME = 1000L * 60 * 30 * 24;
    public static final Long LONG_EXPIRATION_TIME = 1000L * 60 * 60 * 24 * 7;
    public static final String JWT_PREFIX = "Bearer ";
    public static final String BASIC_AUTH_PREFIX = "Basic ";
}
