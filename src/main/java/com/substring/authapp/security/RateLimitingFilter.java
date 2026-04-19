package com.substring.authapp.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.ApiError;
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
 * 3. <b>Evaluation:</b> Attempts to consume a token from the client's assigned {@link Bucket}.
 * 4. <b>Resolution:</b> Allows the request to proceed if tokens are available; otherwise, short-circuits the request with a standardized JSON error.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * - <b>{@link RateLimiterService}</b>: Provides the thread-safe, in-memory token bucket for the client's IP.
 * - <b>{@link ObjectMapper}</b>: Serializes the {@link ApiError} into a standard JSON response.
 * - <b>{@link MessageHelper}</b>: Provides localized error messaging for rate limit violations.
 * </p>
 * 
 * <p><b>Design Rationale (The Short Circuit):</b>
 * By placing this filter early in the Spring Security chain and using {@code return} instead of 
 * {@code filterChain.doFilter()}, we achieve a "Short Circuit." Malicious requests are dropped 
 * before Spring wastes CPU cycles parsing JWTs, connecting to the database, or rendering views.
 * </p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimiterService rateLimiterService;
    private final ObjectMapper objectMapper;
    private final MessageHelper messageHelper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().startsWith("/api/v1/auth")) {
            String ipAddress = getClientIp(request);

            Bucket bucket = rateLimiterService.resolveBucket(ipAddress);
            if (bucket.tryConsume(1)) {
                filterChain.doFilter(request, response);
            } else {
                log.warn("Rate limit exceeded for IP: {}", ipAddress);

                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                String errorMessage = messageHelper.getMessage("auth.otp.cooldown");
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "Too many requests. Please try again later.";
                }

                ApiError error = ApiError.of(
                        HttpStatus.TOO_MANY_REQUESTS.value(),
                        "Too Many Requests",
                        errorMessage,
                        request.getRequestURI()
                );

                response.getWriter().write(objectMapper.writeValueAsString(error));
                return;
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Helper method to find the TRUE IP address.
     * If the app is behind AWS, Nginx, or Cloudflare, the direct IP will just be the proxy's IP.
     * We must check the "X-Forwarded-For" header to find the actual user's IP.
     */
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || !xfHeader.contains((request.getRemoteAddr()))) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}

