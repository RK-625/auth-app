package com.substring.authapp.dtos.admin;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>Administrative User Provisioning Payload</h1>
 * 
 * <p>An inbound Data Transfer Object used by system administrators to manually 
 * create new user accounts. It provides a structured interface for account 
 * initialization while maintaining strict validation rules.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Validation:</b> Enforces administrative-grade password complexity (8+ chars).
 * 2. <b>Assembly:</b> The data is passed to the {@link com.substring.authapp.services.UserService}.
 * 3. <b>Provisioning:</b> Triggers the {@link com.substring.authapp.helpers.UserHelper} to build 
 *    a persistent {@link com.substring.authapp.entities.User} with default roles.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO ensures <b>Mass Assignment Protection</b> even within the 
 * administrative context. By explicitly defining the fields that can be 
 * set during manual creation, we prevent accidental injection of state 
 * that should be managed elsewhere (e.g., social login providers). It 
 * enforces a clean <b>Decoupling</b> between the admin UI and the 
 * internal JPA model, ensuring that the API remains stable and only 
 * validated data reaches the <b>Persistence Context</b>.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminUserCreateRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Required Identity (Fields)
    // ===================================================================================

    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;

    @NotBlank(message = "{user.register.password_required}")
    @Size(min = 6, max = 72, message = "{user.register.password_too_short}")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&]).{6,72}$", 
             message = "{user.register.password_complexity}")
    private String password;

    // ===================================================================================
    // SECTION 2: Optional Profile (Fields)
    // ===================================================================================

    @Size(max = 100)
    private String name;
}

