package com.substring.authapp.dtos;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <h1>Account Recovery Transaction DTO</h1>
 *
 * <p>Data Transfer Object carrying the necessary credentials to execute a 
 * password reset. It encapsulates the identity of the user, the verification 
 * proof (OTP), and the authorization token required for the final update.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Verification Submission:</b> The client sends the {@code email} and {@code otp} 
 *    to the {@code verify} endpoint.
 * 2. <b>Update Submission:</b> Upon successful verification, the client sends 
 *    the {@code resetToken} and the {@code password} (new password) to the 
 *    final {@code reset} endpoint.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This DTO acts as the transport vehicle between the frontend and the 
 * {@link com.substring.authapp.services.AuthService}. It is validated against 
 * the persistent {@link com.substring.authapp.entities.ResetPasswordObject} 
 * to ensure that the recovery flow follows the strictly timed security sequence.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Combining all recovery fields into a single DTO simplifies the controller 
 * signatures and allows for easy validation of the recovery payload. Using 
 * {@link lombok.Data} ensures a concise implementation while providing the 
 * flexibility needed for multi-step form data.
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ForgetPasswordDto {
    /**
     * The 6-digit One-Time Password sent to the user's email.
     */
    @NotBlank(message = "{auth.forget.otp_required}")
    private String otp;

    /**
     * The primary email address of the account to be recovered.
     */
    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;

    /**
     * The new raw password to be set for the account.
     */
    @Size(min = 6, message = "{user.register.password_too_short}")
    private String password;

    /**
     * The temporary UUID token issued after successful OTP verification.
     */
    private String resetToken;
}
