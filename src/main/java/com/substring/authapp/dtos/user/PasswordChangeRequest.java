package com.substring.authapp.dtos.user;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>Self-Service Password Change Payload</h1>
 * 
 * <p>Carries the old and new credentials for an authenticated user 
 * attempting to change their password.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordChangeRequest implements Serializable {

    @NotBlank(message = "{user.register.password_required}")
    private String currentPassword;

    @NotBlank(message = "{user.register.password_required}")
    private String newPassword;
}
