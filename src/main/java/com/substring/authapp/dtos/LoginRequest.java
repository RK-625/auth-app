package com.substring.authapp.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * <h1>Data Transfer Object representing a user's attempt to authenticate.</h1>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> The client sends credentials via a POST request body.
 * 2. <b>Validation:</b> JSR-303/Jakarta Bean Validation constraints ensure the email is properly formatted before any database or security logic is triggered.
 * 3. <b>Handshake:</b> This record is passed to the {@code AuthService} to initiate the {@code AuthenticationManager} verification process.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This DTO acts as a <b>Security Barrier</b>. By validating inputs via <b>@Valid</b> before they 
 * reach the {@link org.springframework.security.authentication.AuthenticationManager}, 
 * we mitigate certain DoS (Denial of Service) vectors that exploit expensive hashing 
 * algorithms (like BCrypt) with malformed or oversized inputs. It also enforces 
 * <b>Mass Assignment Protection</b> by isolating the login contract from the internal 
 * {@link com.substring.authapp.entities.User} entity.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Using a Java {@code record} ensures that credential data is immutable once captured. 
 * The decoupling of this request from the user entity ensures that internal schema 
 * evolutions do not inadvertently break the authentication API for existing clients.
 * </p>
 *
 * @param email The unique email address associated with the user account.
 * @param password The raw password to be verified against the stored hash.
 */
public record LoginRequest(
        @NotBlank(message = "{auth.login.invalid_email}")
        @Email(message = "{auth.login.invalid_email}")
        String email, 
        
        @NotBlank(message = "{auth.login.invalid_credentials}")
        String password
) {

}
