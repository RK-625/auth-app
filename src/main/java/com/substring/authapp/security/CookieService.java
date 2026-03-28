package com.substring.authapp.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

/**
 * Service to manage the lifecycle of security cookies, specifically for refresh tokens.
 * Handles the creation, clearing, and security configuration of cookies.
 */
@Service
@Getter
public class CookieService {

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(@Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName,
                         @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
                         @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
                         @Value("${security.jwt.cookie-domain}") String cookieDomain,
                         @Value("${security.jwt.cookie-same-site}") String cookieSameSite) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieDomain = cookieDomain;
        this.cookieSameSite = cookieSameSite;
    }

    /**
     * Attaches a secure refresh token cookie to the HTTP response.
     * 
     * @param response      The HTTP response to attach the cookie to.
     * @param refreshJWTToken The actual refresh token string.
     * @param maxAge        The time-to-live for the cookie in seconds.
     */
    public void attachRefreshCookie(HttpServletResponse response, String refreshJWTToken, int maxAge) {
        ResponseCookie cookie = buildCookieBase(refreshJWTToken, maxAge);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Clears the refresh token cookie by setting its value to empty and max-age to zero.
     * 
     * @param response The HTTP response to attach the cleared cookie to.
     */
    public void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = buildCookieBase("", 0);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Internal helper to build the standardized cookie structure for both setting and clearing.
     * Applies security constraints like HttpOnly, Secure, SameSite, and Domain.
     */
    private ResponseCookie buildCookieBase(String value, long maxAge) {
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(refreshTokenCookieName, value)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            cookieBuilder.domain(cookieDomain);
        }
        
        return cookieBuilder.build();
    }

    /**
     * Adds Cache-Control headers to prevent sensitive authentication data from being cached.
     */
    public void addNoStoreHeadersToResponse(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
