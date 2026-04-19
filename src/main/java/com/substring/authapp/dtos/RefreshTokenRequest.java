package com.substring.authapp.dtos;

import jakarta.validation.constraints.NotBlank;

/**
 * <h1>Session Extension Request Payload</h1>
 *
 * <p>Data Transfer Object representing a client's request to obtain a new Access Token 
 * using a Refresh Token. This record acts as the primary input for the <b>Refresh Token 
 * Rotation</b> workflow.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> The client provides the {@code refreshToken} string, typically 
 *    when the current access token has expired or is nearing expiration.
 * 2. <b>Extraction:</b> The {@link com.substring.authapp.helpers.TokenHelper} prioritizes 
 *    this DTO field if the token is not present in a secure cookie.
 * 3. <b>Handshake:</b> The token is passed to the {@code AuthService} for cryptographic 
 *    validation and database revocation checks.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This record is automatically deserialized from the JSON request body by the 
 * {@code MappingJackson2HttpMessageConverter}. By using a Java 17+ {@code record}, 
 * we ensure that the request payload is immutable and boilerplate-free.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Providing a specific DTO for refresh requests ensures that the API contract 
 * remains explicit. It allows for future extension (e.g., adding device info or 
 * location data) without breaking the existing refresh interface.
 * </p>
 *
 * @param refreshToken The high-entropy JWT handle used to extend the session.
 */
public record RefreshTokenRequest(
        @NotBlank(message = "Refresh token is required")
        String refreshToken
) {
}
