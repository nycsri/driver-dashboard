package com.driverscanner.security;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
@RestController
public class ApiTokenController {
    public ApiTokenController(ApiTokenProvider tokens) {}
    @GetMapping("/api/token") public Map<String, String> token() { return Map.of(); }
}
