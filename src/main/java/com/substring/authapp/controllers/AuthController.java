package com.substring.authapp.controllers;

import com.substring.authapp.dtos.auth.*;
import com.substring.authapp.services.AuthService;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import com.substring.authapp.helpers.MessageHelper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * Utilizes {@link AuthenticationManager} to delegate credential verification to configured
 * {@code AuthenticationProvider}s. It manages stateless sessions by issuing JSON Web Tokens (JWT)
 * and enforces security best practices like Refresh Token Rotation and secure cookie management.
 * </p>
 *
 * <p><b>Design Rationale (Semantic REST & Delegation):</b>
 * This controller implements a <b>Semantic Status Code</b> strategy, where HTTP response 
 * codes are used to convey fine-grained operation results (e.g., 201 for creation, 
 * 204 for successful session termination). It also follows the <b>Delegation Pattern</b>, 
 * offloading complex cookie and token orchestration to specialized helpers to maintain 
 * a clean, router-only controller layer.
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

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final MessageHelper messageHelper;
    private final MeterRegistry meterRegistry;

    // ===================================================================================
    // SECTION 2: Core Authentication Handshakes
    // ===================================================================================

    /**
     * <h1>Identity Verification & Token Issuance</h1>
     * 
     * <p>Authenticates a user and issues a dual-token response (Access + Refresh).</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Delegates credential verification to the {@link AuthenticationManager}.
     * 2. Orchestrates token generation and cookie injection via {@link AuthService#loginRequest}.
     * 3. Returns the access token and user metadata in the response body.
     * </p>
     *
     * <p><b>Behind the Scenes (The Handshake):</b>
     * The {@code AuthenticationManager} invokes the <b>{@code DaoAuthenticationProvider}</b>. 
     * The provider fetches the stored user and uses the <b>{@code BCryptPasswordEncoder}</b> 
     * to verify the raw password against the stored hash.
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
        TokenResponse tokenResponse = authService.loginRequest(authentication, response);
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * Internal bridge to Spring Security's authentication mechanism.
     */
    private org.springframework.security.core.Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (Exception e) {
            meterRegistry.counter("auth.login.failure").increment();
            throw new BadCredentialsException(messageHelper.getMessage("auth.login.invalid_credentials"));
        }
    }

    /**
     * <h1>Session Renewal (Refresh Token Rotation)</h1>
     * 
     * <p>Issues new Access and Refresh tokens using a valid Refresh Token.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Delegates extraction, rotation, and re-issuance to {@link AuthService#refreshTokenRequest}.
     * 2. Returns a fresh set of tokens to the client.
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
     * @return A fresh set of tokens.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody(required = false) RefreshTokenRequest body, HttpServletResponse response, HttpServletRequest request){
        return ResponseEntity.ok(authService.refreshTokenRequest(body, response, request));
    }

    /**
     * <h1>Session Termination (Logout)</h1>
     * 
     * <p>Terminals the user session by revoking the refresh token and clearing security cookies.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Delegates extraction and revocation orchestration to the {@link AuthService#processLogout}.
     * 2. Returns a 204 No Content status indicating a successful session termination.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * This method follows the <b>Delegation Pattern</b>. By offloading the cookie 
     * and database manipulation to the Service layer, the controller remains 
     * a clean HTTP router focused on semantic status codes.</p>
     *
     * @param body Optional request body containing the refresh token.
     * @param request The current HTTP request.
     * @param response The current HTTP response.
     * @return 204 No Content indicating successful logout.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody(required = false) RefreshTokenRequest body, HttpServletRequest request, HttpServletResponse response){
        authService.processLogout(body, request, response);
        return ResponseEntity.noContent().build();
    }

    // ===================================================================================
    // SECTION 3: Deferred Provisioning Handshake (Signup)
    // ===================================================================================

    /**
     * <h1>Signup Phase 1: Initiation</h1>
     *
     * <p>Initiates the registration process by collecting an email and dispatching an OTP.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the uniqueness of the email address.
     * 2. Creates or updates a temporary {@link com.substring.authapp.entities.SignUpObject}.
     * 3. Dispatches an OTP via email to verify ownership.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Uses a minimalist 200 OK status to indicate successful dispatch without leaking 
     * internal database state to unauthenticated clients.</p>
     *
     * @param request DTO containing registration initiation details (Email).
     * @return 200 OK upon successful OTP dispatch.
     */
    @PostMapping("/signup/request")
    public ResponseEntity<Void> signUpRequestFirst(@Valid @RequestBody SignUpInitiateRequest request) {
        authService.signUpRequest(request);
        return ResponseEntity.ok().build();
    }

    /**
     * <h1>Signup Phase 2: OTP Verification</h1>
     *
     * <p>Verifies the OTP and issues a temporary authorization token to proceed.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the OTP against the stored staging record.
     * 2. Marks the OTP as verified and issues a temporary UUID token.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * The returned UUID token acts as a cryptographic proof that the user successfully 
     * completed the email verification phase before supplying their password.</p>
     *
     * @param request DTO containing the email and OTP.
     * @return A JSON map containing the intermediate verification token.
     */
    @PostMapping("/signup/verifyotp")
    public ResponseEntity<Map<String, String>> signUpRequestSecond(@Valid @RequestBody SignUpVerifyRequest request) {
        String signUpToken = authService.verifySignUpOtp(request.getEmail(), request.getOtp());
        return ResponseEntity.ok(Collections.singletonMap("token", signUpToken));
    }

    /**
     * <h1>Signup Phase 3: Final Provisioning</h1>
     *
     * <p>Finalizes the registration by accepting the password and creating the user entity.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Verifies the previously issued UUID token to ensure phase ordering.
     * 2. Hashes the new password.
     * 3. Persists the final {@link com.substring.authapp.entities.User} entity and cleans up the staging table.
     * </p>
     * 
     * <p><b>Design Rationale:</b>
     * Ensures that sensitive password data is only collected *after* identity verification 
     * is complete, minimizing the attack surface of the temporary staging tables.</p>
     *
     * @param request DTO containing the full profile data and verification tokens.
     * @return 200 OK upon successful account creation.
     */
    @PostMapping("/signup/verifytoken")
    public ResponseEntity<Void> signUpRequestThird(@Valid @RequestBody SignUpCompleteRequest request) {
        authService.verifySignUpToken(request.getEmail(), request.getOtp(), request.getSignUpToken(), request.getPassword());
        return ResponseEntity.ok().build();
    }

    // ===================================================================================
    // SECTION 4: Account Recovery Handshake (Password Reset)
    // ===================================================================================

    /**
     * <h1>Recovery Phase 1: Initiation</h1>
     *
     * <p>Initiates the password recovery process by sending an OTP.</p>
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
     * @param request DTO containing the user's email.
     * @return ResponseEntity with 200 OK status.
     */
    @PostMapping("/forget/email")
    public ResponseEntity<Void> forgetPasswordFirst(@Valid @RequestBody PasswordResetInitiateRequest request) {
        authService.initiatePasswordReset(request.getEmail());
        return ResponseEntity.ok().build();
    }

    /**
     * <h1>Recovery Phase 2: OTP Verification</h1>
     *
     * <p>Verifies the OTP and issues a temporary reset token.</p>
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
     * @param request DTO containing email and OTP.
     * @return A JSON map containing the issued reset token.
     */
    @PostMapping("/forget/otp")
    public ResponseEntity<Map<String, String>> forgetPasswordSecond(@Valid @RequestBody PasswordResetVerifyRequest request) {
        String resetToken = authService.verifyPasswordResetOtp(request.getEmail(), request.getOtp());
        return ResponseEntity.ok(Collections.singletonMap("token", resetToken));
    }

    /**
     * <h1>Recovery Phase 3: Final Reset</h1>
     *
     * <p>Finalizes the password reset using the temporary token and new password.</p>
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
     * @param request DTO containing email, OTP, reset token, and new password.
     * @return ResponseEntity with 200 OK status.
     */
    @PostMapping("/forget/reset")
    public ResponseEntity<Void> forgetPasswordThird(@Valid @RequestBody PasswordResetCompleteRequest request) {
        authService.resetPassword(request.getEmail(), request.getOtp(), request.getResetToken(), request.getPassword());
        return ResponseEntity.ok().build();
    }
}
