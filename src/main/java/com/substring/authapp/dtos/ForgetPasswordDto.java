package com.substring.authapp.dtos;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ForgetPasswordDto {
    private String otp;
    private String email;
    private String password;
    private String resetToken;
}
