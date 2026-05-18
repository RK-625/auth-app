package com.substring.authapp.services;

import com.substring.authapp.dtos.auth.RefreshTokenRequest;
import com.substring.authapp.dtos.auth.SignUpInitiateRequest;
import com.substring.authapp.dtos.auth.TokenResponse;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 * <h1>Authentication & Identity Lifecycle Contract</h1>
 * 
 * <p>Defines the essential operations for managing user identity, session security, 
 * and account recovery. This interface serves as the primary abstraction for 
 * authentication business logic, shielding the controller layer from implementation details.</p>
 * 
 * <p><b>Core Responsibilities:</b>
 * <ul>
 *   <li><b>Provisioning Handshake:</b> Managing the multi-step signup process with deferred entity creation.</li>
 *   <li><b>Account Recovery:</b> Orchestrating secure OTP-based password resets.</li>
 *   <li><b>Session Management:</b> Coordinating the issuance, rotation, and revocation of hybrid refresh tokens.</li>
 * </ul>
 * </p>
 * 
 * @author Gemini CLI
 */
public interface AuthService {

    // ===================================================================================
    // SECTION 1: Registration Handshake (Signup)
    // ===================================================================================

    /**
     * Initiates the signup handshake by generating a temporary verification object.
     * @param request DTO containing the candidate email.
     */
    void signUpRequest(SignUpInitiateRequest request);

    /**
     * Verifies the OTP and issues a temporary signup token.
     * @param email The target email.
     * @param otp The 6-digit verification code.
     * @return A secure UUID string used for final provisioning.
     */
    String verifySignUpOtp(String email, String otp);

    /**
     * Finalizes user creation after successful token verification.
     * @param email The user's email.
     * @param otp The OTP code.
     * @param signUpToken The UUID token from Phase 2.
     * @param password The raw password to be hashed.
     */
    void verifySignUpToken(String email ,String otp ,String signUpToken, String password);

    // ===================================================================================
    // SECTION 2: Recovery Handshake (Password Reset)
    // ===================================================================================
    
    /**
     * Initiates the password reset lifecycle.
     * @param email The user's registered email.
     */
    void initiatePasswordReset(String email);

    /**
     * Validates a reset OTP and issues a reset token.
     * @param email The user's email.
     * @param otp The verification code.
     * @return A secure reset token string.
     */
    String verifyPasswordResetOtp(String email, String otp);

    /**
     * Updates the password using a verified reset token.
     * @param email The user's email.
     * @param otp The verification code.
     * @param resetToken The token issued after OTP verification.
     * @param newPassword The new raw password.
     */
    void resetPassword(String email, String otp, String resetToken, String newPassword);

    // ===================================================================================
    // SECTION 3: Session Management & Security
    // ===================================================================================
    
    /**
     * Creates a new stateful refresh token record.
     * @param user The principal for whom the token is generated.
     * @return The persisted {@link RefreshToken} entity.
     */
    RefreshToken createRefreshToken(User user);

    /**
     * Rotates a refresh token to mitigate replay attacks.
     * @param oldToken The token being consumed.
     * @return A fresh, unrevoked {@link RefreshToken} entity.
     */
    RefreshToken rotateRefreshToken(RefreshToken oldToken);

    /**
     * Revokes a valid refresh token, permanently invalidating the session.
     * 
     * @param refreshTokenStr The raw JWT string.
     */
    void revokeRefreshToken(String refreshTokenStr);

    /**
     * Validates a raw JWT refresh token against security policies and database state.
     * @param refreshTokenStr The raw JWT string.
     * @return The validated {@link RefreshToken} entity.
     */
    RefreshToken getValidatedRefreshToken(String refreshTokenStr);

    // ===================================================================================
    // SECTION 4: Authentication Orchestration (Facade)
    // ===================================================================================

    /**
     * <h1>Identity Verification Orchestrator</h1>
     * 
     * <p>Centralizes the final authentication handshake, token generation, and response construction.</p>
     * 
     * @param authentication The Spring Security authentication object.
     * @param response The HTTP response for cookie injection.
     * @return A complete {@link TokenResponse}.
     */
    TokenResponse loginRequest(Authentication authentication, HttpServletResponse response);

    /**
     * <h1>Session Renewal Orchestrator</h1>
     * 
     * <p>Centralizes the refresh token rotation handshake and response construction.</p>
     * 
     * @param body The refresh request body.
     * @param response The HTTP response for cookie injection.
     * @param request The HTTP request for token extraction.
     * @return A fresh {@link TokenResponse}.
     */
    TokenResponse refreshTokenRequest(RefreshTokenRequest body, HttpServletResponse response, HttpServletRequest request);

    /**
     * <h1>Logout Orchestrator</h1>
     * 
     * <p>Centralizes the session termination logic, including revocation and cookie clearing.</p>
     * 
     * @param body The optional refresh request body.
     * @param request The HTTP request.
     * @param response The HTTP response.
     */
    void processLogout(RefreshTokenRequest body, HttpServletRequest request, HttpServletResponse response);

    /**
     * <h1>Social Authentication Response Generator</h1>
     * 
     * <p>Executes the final security handshake for OAuth2 identities.</p>
     * 
     * @param user The provisioned social user.
     * @param response The HTTP response for cookie injection.
     * @return The generated Access Token string.
     */
    String generateOAuth2AuthenticatedResponse(User user, HttpServletResponse response);
}
