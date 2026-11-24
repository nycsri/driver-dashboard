package com.driverscanner.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Blocks LAN, cross-origin and DNS-rebinding access: every request needs an allowlisted
 * Host on the configured port; state-changing requests also need a same-host Origin
 * (when sent) and the per-process X-DD-Token.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LocalRequestGuardFilter extends OncePerRequestFilter {

    static final String TOKEN_HEADER = "X-DD-Token";
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final int serverPort;
    private final Set<String> allowedHosts;
    private final ApiTokenProvider tokens;

    @Autowired
    public LocalRequestGuardFilter(@Value("${server.port}") int serverPort,
                                   @Value("${driver.security.allowed-hosts}") List<String> allowedHosts,
                                   ApiTokenProvider tokens) {
        this.serverPort = serverPort;
        this.allowedHosts = allowedHosts.stream()
            .map(h -> h.trim().toLowerCase(Locale.ROOT))
            .filter(h -> !h.isEmpty())
            .collect(Collectors.toUnmodifiableSet());
        this.tokens = tokens;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!isAllowedHost(request.getHeader(HttpHeaders.HOST))) {
            reject(response);
            return;
        }
        if (!SAFE_METHODS.contains(request.getMethod().toUpperCase(Locale.ROOT))) {
            String origin = request.getHeader(HttpHeaders.ORIGIN);
            if ((origin != null && !isAllowedOrigin(origin)) || !tokens.matches(request.getHeader(TOKEN_HEADER))) {
                reject(response);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private boolean isAllowedHost(String hostHeader) {
        if (hostHeader == null || hostHeader.isBlank()) {
            return false;
        }
        String h = hostHeader.trim().toLowerCase(Locale.ROOT);
        String host;
        String portPart;
        if (h.startsWith("[")) {
            int close = h.indexOf(']');
            if (close < 0) {
                return false;
            }
            host = h.substring(1, close);
            String rest = h.substring(close + 1);
            if (rest.isEmpty()) {
                portPart = null;
            } else if (rest.startsWith(":")) {
                portPart = rest.substring(1);
            } else {
                return false;
            }
        } else {
            int colon = h.indexOf(':');
            if (colon != h.lastIndexOf(':')) {
                return false;
            }
            host = colon < 0 ? h : h.substring(0, colon);
            portPart = colon < 0 ? null : h.substring(colon + 1);
        }
        // Browsers omit the port only when it is the scheme default; Host carries no scheme, so assume http.
        int port;
        try {
            port = portPart == null ? defaultPort("http") : Integer.parseInt(portPart);
        } catch (NumberFormatException e) {
            return false;
        }
        return port == serverPort && allowedHosts.contains(host);
    }

    private boolean isAllowedOrigin(String origin) {
        URI uri;
        try {
            uri = new URI(origin.trim());
        } catch (Exception e) {
            return false;
        }
        String host = uri.getHost();
        if (host == null || uri.getScheme() == null) {
            return false;
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        int port = uri.getPort() >= 0 ? uri.getPort() : defaultPort(uri.getScheme());
        return port == serverPort && allowedHosts.contains(host);
    }

    private static int defaultPort(String scheme) {
        return "https".equalsIgnoreCase(scheme) ? 443 : 80;
    }

    private static void reject(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"Forbidden\"}");
    }
}
