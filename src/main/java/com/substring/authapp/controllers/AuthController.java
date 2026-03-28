package com.substring.authapp.controllers;

import com.substring.authapp.dtos.*;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;
import com.substring.authapp.helpers.TokenHelper;
import com.substring.authapp.repositories.RefreshTokenRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.CookieService;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import com.substring.authapp.helpers.MessageHelper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * Handles all authentication-related requests including login, registration, 
 * token refresh, and logout.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final TokenHelper tokenHelper;
    private final MessageHelper messageHelper;

    /**
     * Authenticates a user and generates access and refresh tokens.
     * The refresh token is attached as a secure HTTP-only cookie.
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse response){
        org.springframework.security.core.Authentication authentication = authenticate(loginRequest);
        User user = (User) authentication.getPrincipal();

        String accessToken = jwtService.generateAccessToken(user);
        
        RefreshToken refreshTokenOb = authService.createRefreshToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());

        TokenResponse tokenResponse = tokenHelper.generateAuthenticatedResponse(response, user, accessToken, refreshToken);
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * Internal helper to perform Spring Security authentication.
     */
    private org.springframework.security.core.Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (Exception e) {
            throw new BadCredentialsException(messageHelper.getMessage("auth.login.invalid_credentials"));
        }
    }

    /**
     * Rotates the refresh token and issues a new access token.
     * Supports both Cookie-based and Request-body-based refresh tokens.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody(required = false) RefreshTokenRequest body, HttpServletResponse response, HttpServletRequest request){
        String tokenStr = tokenHelper.extractRefreshToken(body, request);
        RefreshToken refreshTokenOb = authService.getValidatedRefreshToken(tokenStr);

        RefreshToken newRefreshTokenOb = authService.rotateRefreshToken(refreshTokenOb);

        String newAccessToken = jwtService.generateAccessToken(refreshTokenOb.getUser());
        String newRefreshToken = jwtService.generateRefreshToken(refreshTokenOb.getUser(), newRefreshTokenOb.getJti());

        TokenResponse tokenResponse = tokenHelper.generateAuthenticatedResponse(
                response, 
                refreshTokenOb.getUser(), 
                newAccessToken, 
                newRefreshToken
        );
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * Revokes the refresh token and clears the authentication context.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody(required = false) RefreshTokenRequest body, HttpServletRequest request, HttpServletResponse response){
        String tokenStr = tokenHelper.extractRefreshToken(body, request);
        RefreshToken refreshTokenOb = authService.getValidatedRefreshToken(tokenStr);
        
        refreshTokenOb.setRevoked(true);
        refreshTokenRepository.save(refreshTokenOb);
        
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeadersToResponse(response);
        SecurityContextHolder.clearContext();
        
        return ResponseEntity.noContent().build();
    }

    /**
     * Creates a new user account.
     */
    @PostMapping("/signup")
    public ResponseEntity<UserDto> signUp(@Valid @RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.signupUser(userDto));
    }

    @PostMapping("/forget/email")
    public ResponseEntity<ForgetPasswordDto> forgetPasswordFirst(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        authService.initiatePasswordReset(forgetPasswordDto.getEmail());
        return ResponseEntity.ok(ForgetPasswordDto.builder().email(forgetPasswordDto.getEmail()).build());
    }

    @PostMapping("/forget/otp")
    public ResponseEntity<ForgetPasswordDto> forgetPasswordSecond(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        String resetToken = authService.verifyPasswordResetOtp(forgetPasswordDto.getEmail(), forgetPasswordDto.getOtp());
        return ResponseEntity.ok(ForgetPasswordDto.builder().email(forgetPasswordDto.getEmail()).resetToken(resetToken).build());
    }

    @PostMapping("/forget/reset")
    public ResponseEntity<ForgetPasswordDto> forgetPasswordThird(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        authService.resetPassword(forgetPasswordDto.getEmail(), forgetPasswordDto.getOtp(), forgetPasswordDto.getResetToken(), forgetPasswordDto.getPassword());
        return ResponseEntity.ok(ForgetPasswordDto.builder().email(forgetPasswordDto.getEmail()).build());
    }
}
