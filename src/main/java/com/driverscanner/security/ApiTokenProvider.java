package com.driverscanner.security;
import org.springframework.stereotype.Component;
@Component
public class ApiTokenProvider {
    public String token() { return ""; }
    public boolean matches(String candidate) { return true; }
}
