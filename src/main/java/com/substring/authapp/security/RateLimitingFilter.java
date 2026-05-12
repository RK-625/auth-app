package com.substring.authapp.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.common.ApiError;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.services.RateLimiterService;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * <h1>API Throttling Security Filter</h1>
 * 
 * <p>Intercepts traffic to sensitive endpoints to enforce Token Bucket rate limits.
 * If a user exhausts their tokens, an immediate 429 (Too Many Requests) is returned, 
 * bypassing the rest of the application logic.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Interception:</b> Checks if the incoming request targets an authentication endpoint.
 * 2. <b>Identification:</b> Extracts the true client IP, accounting for reverse proxies via {@code X-Forwarded-For}.
 * 3. <b>Evaluation:</b> Attempts to consume a token from the client's assigned {@link io.github.bucket4j.Bucket}.
 * 4. <b>Resolution:</b> Allows the request to proceed if tokens are available; otherwise, short-circuits the request with a standardized JSON error.
 * </p>
 * 
 * <p><b>Security Note (The "Two-Cookie" Synchronization):</b>
 * To support the <b>Two-Cookie Pattern</b>, this filter specifically <b>EXCLUDES</b> the 
 * {@code /refresh} and {@code /logout} endpoints from strict throttling via {@link #shouldNotFilter}. 
 * This allows the frontend to perform session-sync checks on page-load without being blocked by 
 * IP-based rate limits designed for brute-force prevention.</p>
 * 
 * @author Gemini CLI
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimiterService rateLimiterService;
    private final ObjectMapper objectMapper;
    private final MessageHelper messageHelper;

    /**
     * <h1>Bypass Strategy</h1>
     * 
     * <p>Determines whether the current request should bypass the rate limiter.</p>
     * 
     * <p><b>Design Rationale:</b>
     * - Only paths under {@code /api/v1/auth} are throttled (to protect login/signup).
     * - We explicitly exclude {@code /refresh} and {@code /logout} so the frontend can safely sync its session state without hitting limits.
     * </p>
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        
        // 1. If it's NOT an auth endpoint, bypass the filter
        if (!uri.startsWith("/api/v1/auth")) {
            return true;
        }
        
        // 2. If it IS an auth endpoint, but it's refresh or logout, bypass the filter
        return uri.endsWith("/refresh") || uri.endsWith("/logout");
    }

    /**
     * Executes the throttling logic for sensitive API paths.
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        // PHASE 1: Identity (IP) Resolution
        String ipAddress = getClientIp(request);

        // PHASE 2: Token Consumption & Short-Circuit Logic
        Bucket bucket = rateLimiterService.resolveBucket(ipAddress);
        
        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            handleThrottlingViolation(request, response, ipAddress);
        }
    }

    /**
     * <h1>Internal Error Dispatcher</h1>
     */
    private void handleThrottlingViolation(HttpServletRequest request, HttpServletResponse response, String ipAddress) throws IOException {
        log.warn("Rate limit exceeded for IP: {}", ipAddress);

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Standardized generic error instead of hardcoded OTP message
        String errorMessage = messageHelper.getMessage("system.error.too_many_requests");
        ApiError error = ApiError.of(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Too Many Requests",
                errorMessage,
                request.getRequestURI()
        );

        response.getWriter().write(objectMapper.writeValueAsString(error));
    }

    /**
     * <h1>True-IP Resolver</h1>
     */
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
