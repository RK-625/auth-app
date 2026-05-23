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
 * <h1>Account Recovery (Phase 3: Completion)</h1>
 * 
 * <p>The terminal inbound payload for the password recovery flow. It carries the 
 * proof of entire recovery handshake completion (Email, OTP, and {@code resetToken}) 
 * along with the user's new permanent security credentials.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Validation:</b> Verifies the {@code resetToken} handle issued in Phase 2.
 * 2. <b>Credential Injection:</b> Transfers the new raw password to the {@link com.substring.authapp.services.AuthService}.
 * 3. <b>Atomic Update:</b> Triggers the secure password re-hashing and persistence update.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO acts as a <b>Security Perimeter</b>. By requiring the {@code resetToken} 
 * along with the OTP, we strictly enforce the sequential integrity of the 
 * recovery process. It provides <b>Mass Assignment Protection</b> by 
 * explicitly defining only the recovery-related fields, ensuring a total 
 * <b>Decoupling</b> between the recovery API and the internal 
 * {@link com.substring.authapp.entities.User} entity. This prevents 
 * unauthorized modification of other user attributes during the 
 * password reset event.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordResetCompleteRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Handshake Context (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;

    @NotBlank(message = "{auth.forget.otp_required}")
    private String otp;

    @NotBlank(message = "{auth.forget.token_required}")
    private String resetToken;

    // ===================================================================================
    // SECTION 2: New Credentials (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.password_required}")
    @Size(min = 6, max = 72, message = "{user.register.password_too_short}")
    private String password;
}
