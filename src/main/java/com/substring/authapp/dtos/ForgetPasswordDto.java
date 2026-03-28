package com.substring.authapp.dtos;


import lombok.RequiredArgsConstructor;

@lombok.Data
@RequiredArgsConstructor
@lombok.Builder
public class ForgetPasswordDto {
    private String otp;
    private String email;
    private String password;
    private String resetToken;
}
