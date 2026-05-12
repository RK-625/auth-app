package com.substring.authapp.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.io.Serializable;

/**
 * <h1>Authentication Request Payload</h1>
 * 
 * <p>The primary inbound Data Transfer Object for the standard login handshake. 
 * It captures the user's identity and proof-of-identity (credentials) 
 * for verification against the secure persistence store.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Collects raw email and password from the HTTP request body.
 * 2. <b>Validation:</b> Spring Validator ensures the email format is correct.
 * 3. <b>Handshake:</b> Passed to {@link org.springframework.security.authentication.AuthenticationManager} 
 *    for credential verification via {@code DaoAuthenticationProvider}.
 * </p>
 * 
 * <p><b>Design Rationale (Decoupling & Mass Assignment Protection):</b>
 * This DTO acts as a critical <b>Security Boundary</b> that enforces strict 
 * <b>Decoupling</b> between the API layer and the {@link com.substring.authapp.entities.User} 
 * entity. By defining an immutable contract for login, it prevents <b>Mass Assignment 
 * Attacks</b>. Even if an attacker injects additional fields (e.g., {@code role=ADMIN}) 
 * into the JSON payload, the application only processes the defined email/password 
 * pair, ensuring the internal state remains protected.</p>
 * 
 * @param email The unique email address associated with the user account.
 * @param password The raw password to be verified against the stored hash.
 */
public record LoginRequest(
        // ===================================================================================
        // SECTION 1: Identity & Proof (Fields)
        // ===================================================================================

        @NotBlank(message = "{auth.login.invalid_email}")
        @Email(message = "{auth.login.invalid_email}")
        String email, 
        
        @NotBlank(message = "{auth.login.invalid_credentials}")
        @Size(min = 6, max = 15, message = "{user.register.password_too_short}")
        String password
) implements Serializable {

}
