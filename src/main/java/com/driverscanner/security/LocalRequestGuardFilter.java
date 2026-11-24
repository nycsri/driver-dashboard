package com.driverscanner.security;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
public class LocalRequestGuardFilter extends OncePerRequestFilter {
    public LocalRequestGuardFilter(int port, List<String> hosts, ApiTokenProvider tokens) {}
    @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException { chain.doFilter(req, res); }
}
