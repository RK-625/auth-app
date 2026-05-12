package com.substring.authapp.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>Signup Handshake (Phase 1: Initiation)</h1>
 * 
 * <p>The initial request payload for starting a new user registration. 
 * This DTO captures the candidate's email to trigger the OTP generation 
 * and delivery process.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Collects the candidate's email address from the registration form.
 * 2. <b>Validation:</b> Spring Validator ensures the email format is correct and not empty.
 * 3. <b>Handshake:</b> Passed to the {@link com.substring.authapp.services.AuthService} 
 *    to check for existing accounts and initiate the OTP flow.
 * </p>
 * 
 * <p><b>Design Rationale (Decoupling & Data Minimization):</b>
 * This DTO serves as a <b>Security Boundary</b>, ensuring that the API 
 * remains <b>Decoupled</b> from the internal persistence model during the 
 * discovery phase. By only requiring the email in Phase 1, we avoid 
 * processing or storing passwords until the user has demonstrated control 
 * over the mailbox, reducing the surface area for brute-force 
 * registration attempts and preventing <b>Mass Assignment</b> of sensitive fields.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignUpInitiateRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Data Carriers (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;
}
