package com.substring.authapp.controllers;

import com.substring.authapp.dtos.*;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.ResetPasswordObject;
import com.substring.authapp.entities.User;
import com.substring.authapp.helpers.TokenHelper;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RefreshTokenRepository;
import com.substring.authapp.repositories.ResetPasswordObjectRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.CookieService;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.services.EmailService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

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
    private final ModelMapper modelMapper;
    private final TokenHelper tokenHelper;
    private final MessageSource messageSource;
    private final Logger logger = org.slf4j.LoggerFactory.getLogger(AuthController.class);
    private final ResetPasswordObjectRepository resetPasswordObjectRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    /**
     * Authenticates a user and generates access and refresh tokens.
     * The refresh token is attached as a secure HTTP-only cookie.
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response){
        authenticate(loginRequest);
        
        User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> new BadCredentialsException(msg("auth.login.invalid_email")));
        
        if (!user.isEnabled()) {
            throw new DisabledException(msg("auth.user.disabled")); 
        }

        String accessToken = jwtService.generateAccessToken(user);
        
        // Generate and persist refresh token for a rotation mechanism
        String refreshTokenJti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(refreshTokenJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefereshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenOb);
        
        String refreshToken = jwtService.generateRefereshToken(user, refreshTokenJti);

        // Generate response using the helper
        TokenResponse tokenResponse = tokenHelper.generateAuthenticatedResponse(response, user, accessToken, refreshToken);
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * Internal helper to perform Spring Security authentication.
     */
    private void authenticate(LoginRequest loginRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (Exception e) {
            throw new BadCredentialsException(msg("auth.login.invalid_credentials"));
        }
    }

    /**
     * Rotates the refresh token and issues a new access token.
     * Supports both Cookie-based and Request-body-based refresh tokens.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody(required = false) RefreshTokenRequest body, HttpServletResponse response, HttpServletRequest request){

        String refreshToken = readRefreshTokenRequest(body, request)
                .orElseThrow(() -> new BadCredentialsException(msg("token.refresh.not_present")));

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException(msg("token.refresh.invalid"));
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUseriD(refreshToken);

        RefreshToken refreshTokenOb = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException(msg("token.refresh.not_found_db")));
        
        // Security checks for token rotation
        if (refreshTokenOb.isRevoked()) throw new BadCredentialsException(msg("token.refresh.revoked"));
        if (refreshTokenOb.getExpiresAt().isBefore(Instant.now())) throw new BadCredentialsException(msg("token.refresh.expired"));
        if (!refreshTokenOb.getUser().getId().equals(userId)) throw new BadCredentialsException(msg("token.refresh.user_mismatch"));

        // Revoke current token and issue new pair (Token Rotation)
        refreshTokenOb.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        refreshTokenOb.setReplacedByToken(newJti);
        refreshTokenRepository.save(refreshTokenOb);

        String newAccessToken = jwtService.generateAccessToken(refreshTokenOb.getUser());
        String newRefreshToken = jwtService.generateRefereshToken(refreshTokenOb.getUser(), newJti);
        
        RefreshToken newRefreshTokenOb = RefreshToken.builder()
                .jti(newJti)
                .revoked(false)
                .user(refreshTokenOb.getUser())
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefereshTtlSeconds()))
                .build();
        refreshTokenRepository.save(newRefreshTokenOb);

        // Generate response using the helper
        TokenResponse tokenResponse = tokenHelper.generateAuthenticatedResponse(
                response, 
                refreshTokenOb.getUser(), 
                newAccessToken, 
                newRefreshToken
        );
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * Extracts refresh token from Cookies or Request Body.
     */
    private Optional<String> readRefreshTokenRequest(RefreshTokenRequest body, HttpServletRequest request) {
        if (request.getCookies() != null) {
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(cookieService.getRefreshTokenCookieName()))
                    .map(Cookie::getValue)
                    .filter(token -> !token.isBlank())
                    .findFirst();
            if (fromCookie.isPresent()) return fromCookie;
        }
        
        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }
        return Optional.empty();
    }

    /**
     * Revokes the refresh token and clears the authentication context.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody(required = false) RefreshTokenRequest body, HttpServletRequest request, HttpServletResponse response){
        String refreshToken = readRefreshTokenRequest(body, request)
                .orElseThrow(() -> new BadCredentialsException(msg("token.refresh.not_present")));
        
        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException(msg("token.refresh.invalid"));
        }
        
        String jti = jwtService.getJti(refreshToken);
        RefreshToken refreshTokenOb = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException(msg("token.refresh.not_found_db")));
        
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
    public ResponseEntity<UserDto> signUp(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.signupUser(userDto));
    }

    @GetMapping("/forget/email")
    public ResponseEntity<ForgetPasswordDto> forgetPasswordFirst(@RequestBody ForgetPasswordDto forgetPasswordDto) {

        if (forgetPasswordDto.getEmail() == null || forgetPasswordDto.getEmail().isBlank()) {
            throw new IllegalArgumentException(msg("auth.forget.email_required"));
        }
        User user = userRepository.findByEmail(forgetPasswordDto.getEmail()).orElseThrow(() -> new BadCredentialsException(msg("auth.forget.email_not_found")));
        var keys = UserHelper.generateSecureOtpAndToken();
        while(resetPasswordObjectRepository.existsByUserAndOtpAndResetToken(user, keys.getFirst(), keys.getSecond())){
            // GENERATE A UNIQUE OTP
            keys = UserHelper.generateSecureOtpAndToken();
        }
        ResetPasswordObject resetPasswordObject = new ResetPasswordObject(user, keys.getFirst(), keys.getSecond());
        resetPasswordObjectRepository.save(resetPasswordObject);
        emailService.sendPassWordResetOtp(user.getEmail(), keys.getFirst());
        return ResponseEntity.ok(ForgetPasswordDto.builder().email(user.getEmail()).build());
    }

    @GetMapping("/forget/otp")
    @Transactional
    public ResponseEntity<ForgetPasswordDto> forgetPasswordSecond(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        if (forgetPasswordDto.getEmail() == null || forgetPasswordDto.getEmail().isBlank()) {
            throw new IllegalArgumentException(msg("auth.forget.email_required"));
        }
        User user = userRepository.findByEmail(forgetPasswordDto.getEmail()).orElseThrow(() -> new BadCredentialsException(msg("auth.forget.email_not_found")));
        ResetPasswordObject resetPasswordObject = resetPasswordObjectRepository.findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(user, forgetPasswordDto.getOtp(), Instant.now()).orElseThrow(() -> new BadCredentialsException("auth.forget.otp_invalid"));
        // HERE means the opt is matching hence send the reset token and set the used to true
        resetPasswordObject.setUsed(true);
        resetPasswordObject.setExpiresAt(Instant.now().plusSeconds(60));
        resetPasswordObjectRepository.save(resetPasswordObject);
        return ResponseEntity.ok(ForgetPasswordDto.builder().email(user.getEmail()).resetToken(forgetPasswordDto.getResetToken()).build());
    }

    @GetMapping("/forget/reset")
    @Transactional
    public ResponseEntity<ForgetPasswordDto> forgetPasswordThird(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        if (forgetPasswordDto.getEmail() == null || forgetPasswordDto.getEmail().isBlank()) {
            throw new IllegalArgumentException(msg("auth.forget.email_required"));
        }
        User user = userRepository.findByEmail(forgetPasswordDto.getEmail()).orElseThrow(() -> new BadCredentialsException(msg("auth.forget.email_not_found")));
        boolean valid = resetPasswordObjectRepository.existsByUserAndResetTokenAndExpiresAtGreaterThan(user, UserHelper.parseUUID(forgetPasswordDto.getResetToken()), Instant.now());
        if(valid){
            user.setPassword(passwordEncoder.encode(forgetPasswordDto.getPassword()));
            userRepository.save(user);
            return ResponseEntity.ok(ForgetPasswordDto.builder().email(user.getEmail()).build());
        }
        return ResponseEntity.badRequest().body(ForgetPasswordDto.builder().build());
    }
    /**
     * Helper to retrieve localized messages from the central library.
     */
    private String msg(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
