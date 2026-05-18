package com.substring.authapp.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>Signup Handshake (Phase 3: Final Provisioning)</h1>
 * 
 * <p>The terminal inbound payload for the multi-phase user registration flow. This DTO carries 
 * the proof of entire handshake completion (Email, OTP, and {@code signUpToken}) 
 * along with the user's permanent security credentials.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Validation:</b> Spring Validator enforces JSR-303 constraints (e.g., password length).
 * 2. <b>Association:</b> Pairs the {@code signUpToken} with the {@code email} to verify handshake state.
 * 3. <b>Atomic Provisioning:</b> Triggers the conversion of temporary staging data into a persistent {@link com.substring.authapp.entities.User}.
 * </p>
 * 
 * <p><b>Behind the Scenes (Stateless Handshake):</b>
 * This DTO represents the final "Commit" signal of a stateless registration process. 
 * No user record exists in the primary {@code users} table until the data in this 
 * object is successfully validated against the temporary {@link com.substring.authapp.entities.SignUpObject} 
 * staging entity within the <b>Persistence Context</b>.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO acts as a <b>Security Perimeter</b>. By explicitly defining only 
 * {@code email}, {@code otp}, {@code signUpToken}, and {@code password}, we prevent 
 * <b>Mass Assignment Attacks</b> where an attacker might try to inject 
 * {@code enabled=true} or {@code role=ADMIN} fields. It ensures a total 
 * <b>Decoupling</b> between the API contract and the internal JPA model, 
 * protecting the system from unauthorized state transitions during the 
 * final account provisioning.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignUpCompleteRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Handshake Context (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;

    @NotBlank(message = "{signup.validation.token_required}")
    private String signUpToken;

    // ===================================================================================
    // SECTION 2: Identity Credentials (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.password_required}")
    @Size(min = 6, max = 15, message = "{user.register.password_too_short}")
    private String password;
}
