package com.substring.authapp.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

/**
 * <h1>Secure Cookie Management Center</h1>
 *
 * <p>Centralizes the lifecycle management of HTTP cookies used for security-sensitive 
 * data, specifically the long-lived JWT Refresh Tokens. It ensures that all cookies 
 * emitted by the application adhere to strict security headers.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Cookie Provisioning:</b> Constructs standardized {@link ResponseCookie} objects with secure defaults.
 * 2. <b>Response Injection:</b> Manages the addition of {@code Set-Cookie} headers to the outgoing response.
 * 3. <b>Security Policy Enforcement:</b> Applies HttpOnly, Secure, and SameSite attributes globally.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This service utilizes Spring's {@link ResponseCookie} to build standardized, 
 * immutable cookie objects. It integrates with {@link HttpServletResponse} 
 * to inject the {@code Set-Cookie} header into outgoing HTTP responses, 
 * ensuring that the browser receives and stores tokens according to the 
 * configured security policy.</p>
 *
 * <p><b>Design Rationale:</b>
 * Storing Refresh Tokens in <b>HttpOnly</b> cookies provides a critical defense 
 * against <b>Cross-Site Scripting (XSS)</b> attacks by preventing client-side 
 * JavaScript from accessing the token. Additionally, the <b>SameSite</b> attribute 
 * mitigates <b>Cross-Site Request Forgery (CSRF)</b> by controlling cross-origin 
 * cookie transmission.</p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.controllers.AuthController
 * @see org.springframework.http.ResponseCookie
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
     * <p><b>Implementation Workflow:</b>
     * 1. Constructs a {@link ResponseCookie} using the provided token and TTL.
     * 2. Applies global security attributes (HttpOnly, Secure, SameSite).
     * 3. Adds the {@code Set-Cookie} header to the {@link HttpServletResponse}.
     * </p>
     *
     * @param response The response to which the cookie will be attached.
     * @param refreshJWTToken The raw JWT refresh token string.
     * @param maxAge The duration (in seconds) the cookie should remain valid in the browser.
     */
    public void attachRefreshCookie(HttpServletResponse response, String refreshJWTToken, int maxAge) {
        ResponseCookie cookie = buildCookieBase(refreshJWTToken, maxAge);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Instructs the browser to remove the refresh token cookie.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Creates a new cookie with the same name but an empty value.
     * 2. Sets the {@code Max-Age} to 0, signaling immediate expiration.
     * 3. Attaches this "clearing" cookie to the response.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * Browsers do not allow the server to "delete" a cookie directly. Instead, 
     * the server must overwrite the existing cookie with an expired version. 
     * The browser then automatically removes the cookie from its storage.</p>
     *
     * @param response The response used to communicate the deletion to the client.
     */
    public void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = buildCookieBase("", 0);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Internal factory for creating standardized {@link ResponseCookie} instances.
     *
     * @param value The value to store in the cookie.
     * @param maxAge TTL in seconds.
     * @return A configured {@link ResponseCookie} ready for transmission.
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
     * Configures headers to prevent browser caching of sensitive responses.
     *
     * <p><b>Behind the Scenes:</b>
     * Sets {@code Cache-Control: no-store} and {@code Pragma: no-cache}. This 
     * ensures that authentication-related data is never written to disk by the 
     * browser or intermediary proxy servers, protecting against information 
     * leakage from shared computers or caches.</p>
     *
     * @param response The HTTP response to secure.
     */
    public void addNoStoreHeadersToResponse(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
