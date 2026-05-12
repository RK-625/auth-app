package com.substring.authapp.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>Signup Handshake (Phase 2: OTP Verification)</h1>
 * 
 * <p>The second inbound payload in the multi-phase registration lifecycle. 
 * This DTO transports the user's proof-of-possession (OTP) to transition the 
 * handshake from "Pending" to "Verified."</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Normalization:</b> Sanitizes the incoming OTP and Email strings.
 * 2. <b>Association:</b> Pairs the OTP with the target identity for lookup.
 * 3. <b>Handshake Transition:</b> Success triggers the issuance of a unique 
 *    {@code signUpToken} handle required for Phase 3.
 * </p>
 * 
 * <p><b>Behind the Scenes (Transactional Integrity):</b>
 * This DTO is validated against the {@link com.substring.authapp.entities.SignUpObject} 
 * persistence store. If the OTP matches, the staging object is marked as verified 
 * within the <b>Persistence Context</b>, preventing re-use of the same OTP for 
 * subsequent verification attempts.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * By isolating Phase 2 into a dedicated DTO, we strictly limit the data surface. 
 * This ensures <b>Decoupling</b> between the verification step and the complex 
 * registration state. It provides <b>Mass Assignment Protection</b> by 
 * explicitly ignoring any fields other than {@code email} and {@code otp}, 
 * ensuring that even if a user is authenticated in another context, they 
 * cannot inject unauthorized state into the registration process.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignUpVerifyRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Verification Context (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;

    @NotBlank(message = "{auth.forget.otp_required}")
    private String otp;
}
