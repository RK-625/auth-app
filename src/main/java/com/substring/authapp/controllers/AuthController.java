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

import java.util.Collections;
import java.util.Map;

/**
 * <h1>Identity & Access Management Controller</h1>
 *
 * <p>The primary entry point for all authentication and authorization lifecycle events.
 * This controller coordinates between Spring Security's infrastructure and the application's
 * business logic to manage user identities, secure sessions, and account recovery.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. Receives security-sensitive requests via REST endpoints.
 * 2. Authenticates principals using the {@link AuthenticationManager} provider chain.
 * 3. Coordinates token lifecycle (issuance, rotation, revocation) via {@link AuthService} and {@link JwtService}.
 * 4. Manages client-side session state through secure, HttpOnly cookie injection.
 * 5. Handles account recovery orchestration (OTP verification and password resets).
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * Utilizes {@link AuthenticationManager} to delegate credential verification to configured
 * {@code AuthenticationProvider}s. It manages stateless sessions by issuing JSON Web Tokens (JWT)
 * and enforces security best practices like Refresh Token Rotation and secure cookie management.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Implements a decoupled authentication architecture where the controller handles HTTP concerns
 * while delegating security logic to specialized services. This ensures that the authentication
 * flow is both robust and easily testable.
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.config.SecurityConfig
 * @see com.substring.authapp.security.JwtService
 * @see com.substring.authapp.services.AuthService
 * @see com.substring.authapp.exceptions.GlobalExceptionHandler
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
     * Authenticates a user and issues a dual-token response (Access + Refresh).
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Delegates credential verification to the {@link AuthenticationManager}.
     * 2. Generates a short-lived JWT Access Token for stateless authorization.
     * 3. Creates and persists a long-lived Refresh Token in the database (Hybrid Session).
     * 4. Attaches the Refresh Token to a Secure, HttpOnly cookie and returns the Access Token.
     * </p>
     *
     * <p><b>Behind the Scenes (The Handshake):</b>
     * The {@code AuthenticationManager} invokes the <b>{@code DaoAuthenticationProvider}</b>. 
     * The provider fetches the stored {@link User} via the <b>{@code CustomUserDetailService}</b> 
     * and uses the <b>{@code BCryptPasswordEncoder}</b> to verify the raw password 
     * against the stored hash.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Using dual tokens balances security and usability. The short-lived Access Token minimizes 
     * the window of misuse, while the Refresh Token allows for seamless session extension.
     * </p>
     *
     * @param loginRequest DTO containing the user's email and raw password.
     * @param response The {@link HttpServletResponse} used to set the secure refresh cookie.
     * @return A {@link TokenResponse} containing the access token and user profile information.
     * @throws BadCredentialsException If the provided email or password is incorrect.
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
     * Internal bridge to Spring Security's authentication mechanism.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Wraps raw credentials into a {@link UsernamePasswordAuthenticationToken}.
     * 2. Passes the token to the {@code authenticationManager.authenticate()} method.
     * 3. Catches any security exceptions and rethrows them with localized error messages.
     * </p>
     *
     * <p><b>Behind the Scenes (Bean Interaction):</b>
     * This method triggers the entire Spring Security provider chain:
     * <ul>
     *   <li>The <b>{@link AuthenticationManager}</b> (typically {@code ProviderManager}) iterates through providers.</li>
     *   <li>The <b>{@code DaoAuthenticationProvider}</b> is selected to handle DB-based login.</li>
     *   <li>The provider calls <b>{@link CustomUserDetailService#loadUserByUsername(String)}</b> to fetch the identity.</li>
     *   <li>The provider then calls <b>{@code PasswordEncoder.matches()}</b> for cryptographic verification.</li>
     * </ul>
     * </p>
     *
     * @param loginRequest The credentials to verify.
     * @return A fully populated authentication object upon success.
     * @throws BadCredentialsException If authentication fails due to invalid credentials.
     */
    private org.springframework.security.core.Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (Exception e) {
            throw new BadCredentialsException(messageHelper.getMessage("auth.login.invalid_credentials"));
        }
    }

    /**
     * Issues new Access and Refresh tokens using a valid Refresh Token.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Extracts the refresh token from either the request body or the secure cookie.
     * 2. Validates the token's existence, expiration, and revocation status.
     * 3. Executes <b>Refresh Token Rotation</b> to invalidate the old token and create a new one.
     * 4. Generates a new JWT Access Token and a new Refresh Token JTI.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * Utilizes {@link AuthService} to manage the {@link RefreshToken} entity lifecycle. The rotation
     * mechanism ensures that if a token is compromised, its reuse will trigger a security alert.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Refresh Token Rotation mitigates the risk of replay attacks. By issuing a new refresh token
     * with every use, the system ensures that stolen tokens have a very limited utility.
     * </p>
     *
     * @param body Optional request body containing the token (for non-cookie clients).
     * @param response The response to update with the new secure cookie.
     * @param request The request to extract the current cookie from.
     * @return A {@link TokenResponse} with fresh tokens.
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
     * Invalidates the current session and clears security credentials.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Extracts and validates the current refresh token.
     * 2. Marks the refresh token as revoked in the database to prevent further use.
     * 3. Clears the HttpOnly refresh cookie from the client's browser.
     * 4. Wipes the {@link SecurityContextHolder} to terminate the current request's authentication context.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * Uses {@link CookieService} to send a 'clearing' cookie with an immediate expiration date.
     * The database update ensures that even if the client retains the token string, it will be
     * rejected by the {@code AuthService} in future requests.
     * </p>
     *
     * @param body Optional request body containing the token.
     * @param request The current HTTP request.
     * @param response The current HTTP response.
     * @return 204 No Content indicating successful logout.
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
     * Registers a new user in the system.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the uniqueness of the email address.
     * 2. Hashes the raw password using a cryptographically strong algorithm.
     * 3. Maps the {@link UserDto} to a {@link User} entity and persists it.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * Delegates to {@link AuthService#signupUser(UserDto)}, which uses {@code BCryptPasswordEncoder}
     * for one-way password hashing before saving the entity via {@code UserRepository}.
     * </p>
     *
     * @param userDto DTO containing registration details.
     * @return The created user profile.
     */
    @PostMapping("/signup/request")
    public ResponseEntity<Void> signUpRequestFirst(@Valid @RequestBody SignUpObjectDto signUpObjectDto) {
        authService.signUpRequest(signUpObjectDto);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/signup/verifyotp")
    public ResponseEntity<Map<String, String>> signUpRequestSecond(@Valid @RequestBody SignUpObjectDto signUpObjectDto) {
        String signUpToken = authService.verifySignUpOtp(signUpObjectDto.getEmail(), signUpObjectDto.getOtp());
        return ResponseEntity.ok(Collections.singletonMap("token", signUpToken));
    }

    @PostMapping("/signup/verifytoken")
    public ResponseEntity<Void> signUpRequestThird(@Valid @RequestBody SignUpObjectDto signUpObjectDto) {
        authService.verifySignUpToken(signUpObjectDto.getEmail(), signUpObjectDto.getOtp(), signUpObjectDto.getSignUpToken().toString(), signUpObjectDto.getPassword());
        return ResponseEntity.ok().build();
    }

    /**
     * Initiates the password recovery process by sending an OTP.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Checks if a user exists with the provided email.
     * 2. Generates a secure One-Time Password (OTP).
     * 3. Dispatches an email containing the OTP to the user.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Uses an OTP to verify identity without requiring a password, facilitating a secure
     * start to the account recovery lifecycle. Returning a 200 OK status indicates 
     * successful dispatch without leaking redundant email data.
     * </p>
     *
     * @param forgetPasswordDto DTO containing the user's email.
     * @return ResponseEntity with 200 OK status.
     */
    @PostMapping("/forget/email")
    public ResponseEntity<Void> forgetPasswordFirst(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        authService.initiatePasswordReset(forgetPasswordDto.getEmail());
        return ResponseEntity.ok().build();
    }

    /**
     * Verifies the OTP and issues a temporary reset token.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the OTP against the stored value and its expiration.
     * 2. If valid, generates a cryptographically secure, short-lived reset token.
     * 3. Returns the reset token to the client for use in the final step.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * The reset token acts as a secondary authentication factor, ensuring that the password
     * change is authorized by the same entity that verified the OTP.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Returns a uniform JSON map {@code {"token": "uuid"}} to standardize the verification 
     * handshake across both Signup and Forget Password flows.
     * </p>
     *
     * @param forgetPasswordDto DTO containing email and OTP.
     * @return A JSON map containing the issued reset token.
     */
    @PostMapping("/forget/otp")
    public ResponseEntity<Map<String, String>> forgetPasswordSecond(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        String resetToken = authService.verifyPasswordResetOtp(forgetPasswordDto.getEmail(), forgetPasswordDto.getOtp());
        return ResponseEntity.ok(Collections.singletonMap("token", resetToken));
    }

    /**
     * Finalizes the password reset using the temporary token and new password.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the reset token and its association with the user.
     * 2. Hashes the new password.
     * 3. Updates the user's password in the database and clears the reset state.
     * </p>
     * 
     * <p><b>Design Rationale:</b>
     * Minimalist return type (Void) to indicate success without redundant data echoing.
     * </p>
     *
     * @param forgetPasswordDto DTO containing email, OTP, reset token, and new password.
     * @return ResponseEntity with 200 OK status.
     */
    @PostMapping("/forget/reset")
    public ResponseEntity<Void> forgetPasswordThird(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        authService.resetPassword(forgetPasswordDto.getEmail(), forgetPasswordDto.getOtp(), forgetPasswordDto.getResetToken(), forgetPasswordDto.getPassword());
        return ResponseEntity.ok().build();
    }
}
