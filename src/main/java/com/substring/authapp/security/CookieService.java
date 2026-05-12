package com.substring.authapp.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

/**
 * <h1>Secure Cookie Management Center (Two-Cookie Pattern)</h1>
 *
 * <p>Centralizes the lifecycle management of HTTP cookies used for security-sensitive 
 * data and frontend session hints. This service implements the <b>"Two-Cookie Pattern"</b> 
 * to synchronize frontend state with backend session persistence.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Cookie Provisioning:</b> Constructs standardized {@link ResponseCookie} objects.
 * 2. <b>The Two-Cookie Handshake:</b>
 *    - <b>Refresh Cookie:</b> A secure, {@code HttpOnly} token for session renewal.
 *    - <b>Logged-In Hint:</b> A public cookie readable by JS to prevent "blind pings" to the API.
 * 3. <b>Security Policy Enforcement:</b> Applies HttpOnly, Secure, and SameSite attributes globally.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Storing Refresh Tokens in <b>HttpOnly</b> cookies prevents <b>XSS</b> theft. However, 
 * since JS cannot read them, the frontend often "blindly" calls the refresh API on page load. 
 * By adding a parallel, non-HttpOnly {@code logged_in=true} cookie with the exact same 
 * expiry, the frontend can check for this "hint" before making expensive API calls, 
 * significantly reducing server load and preventing rate-limit triggers.
 * </p>
 *
 * @author Gemini CLI
 */
@Service
@Getter
public class CookieService {

    // ===================================================================================
    // SECTION 1: Infrastructure & Configuration (Fields)
    // ===================================================================================

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;
    private final String loggedInHintName = "logged_in";

    // ===================================================================================
    // SECTION 2: Constructor (Dependency Injection)
    // ===================================================================================

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

    // ===================================================================================
    // SECTION 3: Cookie Lifecycle Management (Public)
    // ===================================================================================

    /**
     * Attaches the two-cookie set to the HTTP response.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Attaches the {@code HttpOnly} refresh token for security.
     * 2. Attaches the {@code non-HttpOnly} logged_in hint for the frontend.
     * </p>
     *
     * @param response The response to which the cookies will be attached.
     * @param refreshJWTToken The raw JWT refresh token string.
     * @param maxAge The duration (in seconds) both cookies should remain valid.
     */
    public void attachRefreshCookie(HttpServletResponse response, String refreshJWTToken, int maxAge) {
        // 1. Attach Secure Token
        ResponseCookie tokenCookie = buildCookie(refreshTokenCookieName, refreshJWTToken, maxAge, true);
        response.addHeader(HttpHeaders.SET_COOKIE, tokenCookie.toString());

        // 2. Attach Frontend Hint
        ResponseCookie hintCookie = buildCookie(loggedInHintName, "true", maxAge, false);
        response.addHeader(HttpHeaders.SET_COOKIE, hintCookie.toString());
    }

    /**
     * Instructs the browser to remove both session cookies.
     *
     * @param response The response used to communicate the deletion to the client.
     */
    public void clearRefreshCookie(HttpServletResponse response) {
        // 1. Clear Secure Token
        ResponseCookie tokenCookie = buildCookie(refreshTokenCookieName, "", 0, true);
        response.addHeader(HttpHeaders.SET_COOKIE, tokenCookie.toString());

        // 2. Clear Frontend Hint
        ResponseCookie hintCookie = buildCookie(loggedInHintName, "", 0, false);
        response.addHeader(HttpHeaders.SET_COOKIE, hintCookie.toString());
    }

    // ===================================================================================
    // SECTION 4: Response Hardening (Security Headers)
    // ===================================================================================

    /**
     * Configures headers to prevent browser caching of sensitive responses.
     */
    public void addNoStoreHeadersToResponse(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Pragma", "no-cache");
    }

    // ===================================================================================
    // SECTION 5: Cookie Provisioning Engine (Internal)
    // ===================================================================================

    /**
     * Internal factory for creating standardized {@link ResponseCookie} instances.
     *
     * @param name Name of the cookie.
     * @param value Value of the cookie.
     * @param maxAge TTL in seconds.
     * @param httpOnly Whether JavaScript can read the cookie.
     * @return A configured {@link ResponseCookie}.
     */
    private ResponseCookie buildCookie(String name, String value, long maxAge, boolean httpOnly) {
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(name, value)
                .httpOnly(httpOnly)
                .secure(cookieSecure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            cookieBuilder.domain(cookieDomain);
        }
        
        return cookieBuilder.build();
    }
}
