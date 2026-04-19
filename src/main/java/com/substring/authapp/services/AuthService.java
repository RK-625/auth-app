package com.substring.authapp.services;

import com.substring.authapp.dtos.SignUpObjectDto;
import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;

public interface AuthService {
    void signUpRequest(SignUpObjectDto signUpObjectDto);
    String verifySignUpOtp(String email, String otp);
    void verifySignUpToken(String email ,String otp ,String signUpToken, String password);
    // Password reset flow
    void initiatePasswordReset(String email);
    String verifyPasswordResetOtp(String email, String otp);
    void resetPassword(String email, String otp, String resetToken, String newPassword);
    
    // Token management
    RefreshToken createRefreshToken(User user);
    RefreshToken rotateRefreshToken(RefreshToken oldToken);
    RefreshToken getValidatedRefreshToken(String refreshTokenStr);
}
