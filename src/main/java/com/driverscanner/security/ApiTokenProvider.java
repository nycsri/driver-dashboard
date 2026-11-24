package com.driverscanner.security;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Per-process random token that state-changing requests must echo in X-DD-Token. */
@Component
public class ApiTokenProvider {

    private static final int TOKEN_BYTES = 32;

    private final String token;
    private final byte[] tokenBytes;

    public ApiTokenProvider() {
        byte[] raw = new byte[TOKEN_BYTES];
        new SecureRandom().nextBytes(raw);
        this.token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        this.tokenBytes = token.getBytes(StandardCharsets.US_ASCII);
    }

    public String token() {
        return token;
    }

    public boolean matches(String candidate) {
        if (candidate == null) {
            return false;
        }
        return MessageDigest.isEqual(tokenBytes, candidate.getBytes(StandardCharsets.US_ASCII));
    }
}
