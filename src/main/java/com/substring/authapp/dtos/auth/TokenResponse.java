package com.substring.authapp.dtos.auth;

import com.substring.authapp.dtos.user.AuthUserResponse;
import lombok.Builder;

import java.io.Serializable;

/**
 * <h1>Authentication Payload DTO</h1>
 * 
 * <p>The terminal response object for every successful authentication event 
 * (Login, Token Refresh, Social Login). It carries the stateless Access Token 
 * and the minimalist user profile.</p>
 * 
 * <p><b>Behind the Scenes (Hybrid Security Model):</b>
 * This record facilitates a <b>Stateful Stateless</b> architecture. While the 
 * Access JWT is stateless, the associated Refresh Token is stored in a secure 
 * HttpOnly cookie and backed by a database entry. This allows for a 
 * <b>Kill-Switch</b> mechanism to revoke sessions immediately if needed.</p>
 * 
 * <p><b>Design Rationale (Privacy by Design & Decoupling):</b>
 * This DTO provides essential <b>Decoupling</b> by projecting a safe, 
 * consumer-friendly view of the authentication state. It <b>physically lacks</b> 
 * a {@code refreshToken} field; by keeping the refresh token exclusively in an 
 * HttpOnly cookie, we protect the session from XSS (Cross-Site Scripting) theft. 
 * This ensures that the frontend receives only the data it needs to function, 
 * while the persistent session handle remains managed securely by the server.</p>
 * 
 * @param accessToken The JWT used for authorized requests.
 * @param expiresIn Time in seconds until the access token expires.
 * @param tokenType The authorization scheme (e.g., Bearer).
 * @param user Flattened profile metadata of the authenticated user.
 */
@Builder
public record TokenResponse(
        // ===================================================================================
        // SECTION 1: Secure Context (Fields)
        // ===================================================================================

        String accessToken, 
        long expiresIn, 
        String tokenType, 
        AuthUserResponse user
) implements Serializable {

    // ===================================================================================
    // SECTION 2: Domain Helpers (Static Factories)
    // ===================================================================================

    /**
     * Static factory method to create a standardized Bearer token response.
     */
    public static TokenResponse of(String accessToken, long expiresIn, String tokenType, AuthUserResponse user) {
        return new TokenResponse(accessToken, expiresIn, tokenType, user);
    }
}
