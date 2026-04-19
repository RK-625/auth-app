package com.substring.authapp.dtos;

import lombok.Builder;

/**
 * <h1>Data Transfer Object carrying the successful authentication payload.</h1>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Token Generation:</b> The {@code JwtService} signs and encodes the claims into a compact JWT string.
 * 2. <b>Assembly:</b> The {@code AuthService} bundles the access token, refresh token, and user metadata into this record.
 * 3. <b>Serialization:</b> Jackson serializes this record into a JSON object for the final HTTP 200 OK response.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This record facilitates <b>API/Entity Decoupling</b>. By explicitly defining the return structure, we ensure 
 * that the internal {@link com.substring.authapp.entities.User} entity—which may contain sensitive fields like 
 * password hashes or internal audit trails—is never directly exposed to the network. This acts as a 
 * <b>Mass Assignment Protection</b> layer by controlling exactly what the client can see and interact with.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * We use a Java {@code record} for immutability and boilerplate reduction. The inclusion of {@code expiresIn} 
 * and {@code tokenType} (Bearer) ensures compliance with OAuth2 standards, allowing client-side libraries 
 * to handle automatic token refresh and authorization header construction predictably.
 * </p>
 *
 * @param accessToken The JWT used for authorized requests.
 * @param refreshToken The high-entropy handle for obtaining new access tokens.
 * @param expiresIn Time in seconds until the access token expires.
 * @param tokenType The authorization scheme (defaults to Bearer).
 * @param user Flattened profile metadata of the authenticated user.
 */
@Builder
public record TokenResponse(String accessToken,String refreshToken,long expiresIn,String tokenType,UserDto user) {
    /**
     * Static factory method to create a standardized Bearer token response.
     *
     * @return A {@link TokenResponse} with the token type pre-set to "Bearer".
     */
    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, String tokenType,UserDto user) {
        return new TokenResponse(accessToken, refreshToken, expiresIn, "Bearer", user);
    }
}
