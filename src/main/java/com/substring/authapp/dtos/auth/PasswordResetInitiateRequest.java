package com.substring.authapp.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>Account Recovery (Phase 1: Initiation)</h1>
 * 
 * <p>The initial inbound Data Transfer Object for starting a password recovery flow. 
 * It captures the user's email to trigger the generation and delivery 
 * of a secure recovery OTP.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Receives the candidate email for account recovery.
 * 2. <b>Validation:</b> Spring Validator ensures the email format is correct.
 * 3. <b>Trigger:</b> Commands the {@link com.substring.authapp.services.AuthService} 
 *    to generate a recovery handshake and dispatch an OTP email.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO enforces <b>Mass Assignment Protection</b> by isolating the 
 * initiation request from any other user attributes. By only requiring 
 * the email, we avoid processing or storing any other data until the 
 * user has demonstrated control over the mailbox. It provides a clean 
 * <b>Decoupling</b> between the recovery start signal and the 
 * complex underlying recovery state machine, ensuring the API contract 
 * remains stable regardless of internal schema changes.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordResetInitiateRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Data Carriers (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;
}
