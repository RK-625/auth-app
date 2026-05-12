package com.substring.authapp.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>Account Recovery (Phase 2: OTP Verification)</h1>
 * 
 * <p>The second inbound payload in the password recovery lifecycle. 
 * This DTO transports the user's proof-of-possession (OTP) to transition the 
 * recovery handshake from "Initiated" to "Verified."</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Receives the recovery OTP entered by the user.
 * 2. <b>Association:</b> Pairs the OTP with the target identity for lookup.
 * 3. <b>Handshake Transition:</b> Success triggers the issuance of a unique 
 *    {@code resetToken} required for the final Phase 3 request.
 * </p>
 * 
 * <p><b>Behind the Scenes (Transactional Integrity):</b>
 * This DTO is validated against the {@link com.substring.authapp.entities.ResetPasswordObject} 
 * persistence store. A successful match marks the recovery intent as verified 
 * within the <b>Persistence Context</b>, authorizing the generation of the final 
 * reset token.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * By isolating Phase 2 into a dedicated DTO, we strictly limit the data surface. 
 * This ensures <b>Decoupling</b> between the verification step and the final 
 * credential update step. It provides <b>Mass Assignment Protection</b> by 
 * explicitly defining only the recovery-related fields, ensuring that even if 
 * an attacker attempts to inject a new password during verification, it will 
 * be ignored by the system.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordResetVerifyRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Verification Context (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;

    @NotBlank(message = "{auth.forget.otp_required}")
    private String otp;
}
