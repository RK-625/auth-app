package com.substring.authapp.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "{auth.login.invalid_email}")
        @Email(message = "{auth.login.invalid_email}")
        String email, 
        
        @NotBlank(message = "{auth.login.invalid_credentials}")
        String password
) {

}
