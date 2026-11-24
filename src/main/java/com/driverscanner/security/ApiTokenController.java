package com.driverscanner.security;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Same-origin pages read the token here; the Host check in front of it blocks rebinding pages. */
@RestController
public class ApiTokenController {

    private final ApiTokenProvider tokens;

    public ApiTokenController(ApiTokenProvider tokens) {
        this.tokens = tokens;
    }

    @GetMapping("/api/token")
    public ResponseEntity<Map<String, String>> token() {
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())
            .body(Map.of("token", tokens.token()));
    }
}
