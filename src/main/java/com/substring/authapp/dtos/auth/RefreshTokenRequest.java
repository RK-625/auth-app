package com.substring.authapp.dtos.auth;

import jakarta.validation.constraints.NotBlank;

import java.io.Serializable;

/**
 * <h1>Session Extension Request Payload</h1>
 *
 * <p>An inbound Data Transfer Object representing a client's request to obtain a 
 * new Access Token using a Refresh Token. This DTO is used when the client 
 * cannot or does not use the secure {@code HttpOnly} cookie for token storage.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Extracts the high-entropy token from the request body.
 * 2. <b>Delegation:</b> The {@link com.substring.authapp.helpers.TokenHelper} 
 *    validates the token presence in either the body or cookies.
 * 3. <b>Revocation/Rotation:</b> Triggers the token rotation logic in 
 *    {@link com.substring.authapp.services.AuthService}.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO enforces <b>Mass Assignment Protection</b> by isolating the 
 * {@code refreshToken} string from any other session metadata. It provides 
 * <b>Decoupling</b> by ensuring that the client doesn't need to know about 
 * the internal database structure of the {@link com.substring.authapp.entities.RefreshToken} 
 * entity, only providing the raw token handle. This separates the public 
 * handshake handle from the internal persistence state.</p>
 *
 * @param refreshToken The high-entropy JWT handle used to extend the session.
 */
public record RefreshTokenRequest(
        // ===================================================================================
        // SECTION 1: Handshake Context (Fields)
        // ===================================================================================

        @NotBlank(message = "Refresh token is required")
        String refreshToken
) implements Serializable {
}
