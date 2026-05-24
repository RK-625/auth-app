package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.auth.RefreshTokenRequest;
import com.substring.authapp.dtos.auth.SignUpInitiateRequest;
import com.substring.authapp.dtos.auth.TokenResponse;
import com.substring.authapp.dtos.user.AuthUserResponse;
import com.substring.authapp.entities.*;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.*;
import com.substring.authapp.security.CookieService;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.services.EmailService;
import com.substring.authapp.services.UserService;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.substring.authapp.helpers.MessageHelper;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Authentication Business Logic Provider (Hybrid Session)</h1>
 *
 * <p>Implements the core business rules for user identity management, session maintenance, 
 * and account recovery. This service acts as the orchestration layer between the 
 * security infrastructure and the persistence layer, implementing a <b>Hybrid Session</b> model.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Identity Verification:</b> Validates credentials and account status during login/signup.
 * 2. <b>Upsert Pattern:</b> Maintains lean staging tables by updating existing handshake objects 
 *    instead of duplicate record creation.
 * 3. <b>Transaction Synchronization:</b> Guarantees that side effects like email dispatch 
 *    only occur upon successful database commit.
 * 4. <b>Web-Aware Orchestration:</b> Deliberately handles HTTP-level orchestration (Cookies, Redirects) 
 *    to centralize the authentication lifecycle and simplify the controller layer.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This service interacts with multiple Spring-managed beans to fulfill the security contract:
 * <ul>
 *   <li>{@link PasswordEncoder}: Utilizes {@code BCryptPasswordEncoder} for one-way, salted password hashing.</li>
 *   <li>{@link JwtService}: Manages the cryptographic signing and parsing of stateless JSON Web Tokens.</li>
 *   <li>{@link CookieService}: Manages the injection and clearing of secure HTTP-only cookies.</li>
 *   <li>{@link ModelMapper}: Ensures safe projection of internal entities into API DTOs.</li>
 * </ul>
 * It also manages {@link RefreshToken} and {@link ResetPasswordObject} entities, 
 * enforcing transactional boundaries via {@link Transactional} to ensure data integrity.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * While traditionally services remain protocol-agnostic, this service adopts the <b>Facade Service</b> 
 * pattern. By accepting {@link HttpServletResponse}, it centralizes the entire security handshake, 
 * ensuring that cookie management and database revocation are always perfectly synchronized, 
 * reducing the risk of orphaned sessions or missing security cookies.
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.services.AuthService
 * @see com.substring.authapp.security.JwtService
 * @see com.substring.authapp.helpers.UserHelper
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    // ===================================================================================
    // SECTION 1: Infrastructure & Configuration (Fields)
    // ===================================================================================

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final UserHelper userHelper;
    private final MessageHelper messageHelper;
    private final RoleRepository roleRepository;
    private final SignUpObjectRepository signUpObjectRepository;
    private final ResetPasswordObjectRepository resetPasswordObjectRepository;
    private final EmailService emailService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;
    private final MeterRegistry meterRegistry;

    @Value("${security.otp.initial-ttl-seconds:300}")
    private long initialTtl;

    @Value("${security.otp.grace-period-ttl-seconds:60}")
    private long gracePeriodTtl;

    // ===================================================================================
    // SECTION 2: Core Authentication Facade (The "Public API")
    // ===================================================================================

    /**
     * <h1>Identity Verification Orchestrator</h1>
     * 
     * <p>Centralizes the final authentication handshake, token generation, and response construction. 
     * This method acts as a <b>Web-Aware Facade</b>, deliberately accepting {@link HttpServletResponse} 
     * to manage cookie injection alongside business logic.</p>
     * 
     * @param authentication The Spring Security authentication object.
     * @param response The HTTP response for cookie injection.
     * @return A complete {@link TokenResponse}.
     */
    @Override
    public TokenResponse loginRequest(Authentication authentication, HttpServletResponse response) {
        User user = (User) authentication.getPrincipal();
        String accessToken = jwtService.generateAccessToken(user);

        RefreshToken refreshTokenOb = createRefreshToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());

        meterRegistry.counter("auth.login.success").increment();
        return generateAuthenticatedResponse(response, user, accessToken, refreshToken);
    }

    /**
     * <h1>Session Renewal Orchestrator</h1>
     * 
     * <p>Centralizes the refresh token rotation handshake and response construction. 
     * By handling extraction and rotation here, we ensure that the session lifecycle 
     * is atomically managed within the service layer.</p>
     * 
     * @param body The refresh request body.
     * @param response The HTTP response for cookie injection.
     * @param request The HTTP request for token extraction.
     * @return A fresh {@link TokenResponse}.
     */
    @Override
    public TokenResponse refreshTokenRequest(RefreshTokenRequest body, HttpServletResponse response, HttpServletRequest request) {
        String tokenStr = extractRefreshToken(body, request);
        RefreshToken refreshTokenOb = getValidatedRefreshToken(tokenStr);

        RefreshToken newRefreshTokenOb = rotateRefreshToken(refreshTokenOb);

        String newAccessToken = jwtService.generateAccessToken(refreshTokenOb.getUser());
        String newRefreshToken = jwtService.generateRefreshToken(refreshTokenOb.getUser(), newRefreshTokenOb.getJti());

        return generateAuthenticatedResponse(response, refreshTokenOb.getUser(), newAccessToken, newRefreshToken);
    }

    /**
     * <h1>Logout Orchestrator</h1>
     * 
     * <p>Centralizes the session termination logic, including revocation and cookie clearing.</p>
     * 
     * @param body The optional refresh request body.
     * @param request The HTTP request.
     * @param response The HTTP response.
     */
    @Override
    @Transactional
    public void processLogout(RefreshTokenRequest body, HttpServletRequest request, HttpServletResponse response) {
        try {
            // 1. Extract the token using the hierarchical strategy
            String token = extractRefreshToken(body, request);

            // 2. Business logic: Revoke in Database (Hybrid Session Kill-Switch)
            revokeRefreshToken(token);
        } catch (Exception e) {
            // Log as debug or info to avoid noise, as logout can naturally fail if token is already expired
            log.info("Logout: No active session found to revoke in DB ({}). Proceeding to clear local state.", e.getMessage());
        } finally {
            // 3. Response logic: Clear browser cookies (MANDATORY for frontend sync)
            cookieService.clearRefreshCookie(response);

            // 4. Security logic: Wipe thread-local authentication
            SecurityContextHolder.clearContext();
        }
    }

    // ===================================================================================
    // SECTION 3: Registration Orchestration (Signup)
    // ===================================================================================

    /**
     * <h1>Signup Phase 1: Initiation</h1>
     * 
     * <p>Initiates the multi-step user registration handshake. This method implements 
     * the <b>Deferred Provisioning</b> pattern by creating a temporary {@link SignUpObject} 
     * instead of a full {@link User} entity, preventing unverified accounts from 
     * polluting the primary identity table. Password collection is deferred to Phase 3.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Validation:</b> Verifies email uniqueness via {@link UserHelper}.
     * 2. <b>Upsert Pattern:</b>
     *    - If an active signup exists, it refreshes the OTP and resets the 5-minute expiry.
     *    - If not, it generates new unique credentials and persists a fresh record.
     * 3. <b>Synchronization:</b> Dispatches the verification code via {@link EmailService} 
     *    ONLY after the transaction successfully commits.
     * </p>
     * 
     * @param request DTO containing the candidate user's email.
     */
    @Override
    @Transactional
    public void signUpRequest(SignUpInitiateRequest request) {
        userHelper.validateSignUpEmail(request.getEmail());

        Optional<SignUpObject> signUpObjectOpt = signUpObjectRepository.findByEmail(request.getEmail());

        String finalOtp;
        if (signUpObjectOpt.isPresent()) {
            SignUpObject existing = signUpObjectOpt.get();

            // COOLDOWN CHECK: Prevent spamming (60 seconds)
            if (existing.getLastSentAt().plusSeconds(60).isAfter(Instant.now())) {
                throw new BadCredentialsException(messageHelper.getMessage("auth.otp.cooldown"));
            }

            var newKeys = userHelper.generateUniqueHandshakeKeys(keys -> 
                signUpObjectRepository.existsByEmailAndOtpAndExpiresAtGreaterThan(request.getEmail(), keys.getFirst(), Instant.now())
            );
            existing.refreshOtp(newKeys.getFirst(), initialTtl);
            finalOtp = newKeys.getFirst();
            signUpObjectRepository.save(existing);
        } else {
            // CONCURRENCY HARDENING: Atomic cleanup of potential stale records 
            // for the same email that might have been inserted between the check and here.
            signUpObjectRepository.deleteByEmail(request.getEmail());

            // Use Generic Factory for new requests
            var keys = userHelper.generateUniqueHandshakeKeys(k -> false); // New record for this email
            SignUpObject newSignup = new SignUpObject(request.getEmail(), keys.getFirst(), keys.getSecond(), initialTtl);
            signUpObjectRepository.save(newSignup);
            finalOtp = keys.getFirst();
        }

        // Transaction Synchronization: Only send email if the DB commit succeeds
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                emailService.sendSignUpOtp(request.getEmail(), finalOtp);
            }
        });
    }

    /**
     * <h1>Signup Phase 2: OTP Verification</h1>
     * 
     * <p>Validates the user's possession of the verification code and transitions 
     * the handshake to its terminal phase. This step triggers the <b>Two-Phase Expiry</b> 
     * contraction to minimize the security window.</p>
     * 
     * @param email The target user email.
     * @param otp The 6-digit verification code.
     * @return A secure UUID string used for Phase 3.
     * @throws BadCredentialsException If the OTP is invalid or expired.
     */
    @Override
    @Transactional
    public String verifySignUpOtp(String email ,String otp){
        userHelper.validateSignUpEmail(email);
        SignUpObject signUpObject = signUpObjectRepository
                .findByEmailAndOtpAndExpiresAtGreaterThan(email, otp, Instant.now())
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid")));

        // Mandatory state transition for security
        signUpObject.setExpiresAt(Instant.now().plusSeconds(gracePeriodTtl));
        signUpObject.setUsed(true);
        signUpObjectRepository.save(signUpObject);

        return signUpObject.getSignUpToken().toString();
    }

    /**
     * <h1>Signup Phase 3: Final Provisioning</h1>
     * 
     * <p>The terminal point of the <b>Deferred Provisioning</b> handshake. Converts 
     * the verified signup state into a permanent user identity and performs 
     * immediate cleanup of the staging record.</p>
     * 
     * @param email User email.
     * @param signUpToken UUID token issued in Phase 2.
     * @param password The raw password for the new account.
     */
    @Override
    @Transactional
    public void verifySignUpToken(String email, String signUpToken, String password) {
        userHelper.validateUserForSignup(email, password); 

        // Critical: Check for used=true to prevent Phase 2 bypass
        SignUpObject validObject = signUpObjectRepository
                .findByEmailAndExpiresAtGreaterThanAndSignUpToken(email, Instant.now(), UUID.fromString(signUpToken))
                .filter(SignUpObject::isUsed) // Enforce that OTP was verified
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("signup.validation.failure")));

        // Execute atomic account creation
        userHelper.buildAndSaveUser(email, password, null, Provider.LOCAL, UserRole.ROLE_USER);

        // Atomic cleanup
        signUpObjectRepository.delete(validObject);
    }

    // ===================================================================================
    // SECTION 4: Recovery Orchestration (Password Reset)
    // ===================================================================================

    /**
     * <h1>Recovery Phase 1: Initiation</h1>
     * 
     * <p>Initiates the password recovery lifecycle. This method implements the 
     * <b>Upsert Pattern</b> for the reset handshake.</p>
     *
     * @param email The user's email address.
     */
    @Override
    @Transactional
    public void initiatePasswordReset(String email) {
        User user = userHelper.validateAndGetUserForAuth(email);
        Optional<ResetPasswordObject> activeOtp = resetPasswordObjectRepository.findByUserAndExpiresAtGreaterThan(user, Instant.now());

        if (activeOtp.isPresent()) {
            ResetPasswordObject existing = activeOtp.get();

            // COOLDOWN CHECK: Prevent spamming (60 seconds)
            if (existing.getLastSentAt().plusSeconds(60).isAfter(Instant.now())) {
                throw new BadCredentialsException(messageHelper.getMessage("auth.otp.cooldown"));
            }

            // Reuse Generic Factory for refresh
            var newKeys = userHelper.generateUniqueHandshakeKeys(k -> 
                resetPasswordObjectRepository.existsByUserAndOtpAndResetToken(user, k.getFirst(), k.getSecond())
            );
            existing.refreshOtp(newKeys.getFirst(), initialTtl);
            resetPasswordObjectRepository.save(existing);

            // Transaction Synchronization: Only send email if the DB commit succeeds
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    emailService.sendPassWordResetOtp(user.getEmail(), newKeys.getFirst());
                }
            });
        } else {
            resetPasswordObjectRepository.deleteAllByUser(user);

            // Use Generic Factory for new requests
            var keys = userHelper.generateUniqueHandshakeKeys(k -> 
                resetPasswordObjectRepository.existsByUserAndOtpAndResetToken(user, k.getFirst(), k.getSecond())
            );

            ResetPasswordObject resetPasswordObject = new ResetPasswordObject(user, keys.getFirst(), keys.getSecond(), initialTtl);
            resetPasswordObjectRepository.save(resetPasswordObject);

            // Transaction Synchronization: Only send email if the DB commit succeeds
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    emailService.sendPassWordResetOtp(user.getEmail(), keys.getFirst());
                }
            });
        }
    }

    /**
     * <h1>Recovery Phase 2: OTP Verification</h1>
     * 
     * <p>Validates a password reset OTP and issues a temporary authorization token.</p>
     *
     * @param email The user's email.
     * @param otp The 6-digit OTP code.
     * @return A secure reset token string.
     * @throws BadCredentialsException If the OTP is invalid, expired, or already used.
     */
    @Override
    @Transactional
    public String verifyPasswordResetOtp(String email, String otp) {
        User user = userHelper.validateAndGetUserForAuth(email);

        ResetPasswordObject resetPasswordObject = resetPasswordObjectRepository
                .findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(user, otp, Instant.now())
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid")));

        // Mark OTP as verified/used
        resetPasswordObject.setUsed(true);
        // Provide a dynamic grace period for the client to submit the new password
        resetPasswordObject.setExpiresAt(Instant.now().plusSeconds(gracePeriodTtl));
        resetPasswordObjectRepository.save(resetPasswordObject);

        return resetPasswordObject.getResetToken().toString();
    }

    /**
     * <h1>Recovery Phase 3: Final Reset</h1>
     * 
     * <p>Updates a user's password using a verified reset token.</p>
     *
     * @param email The user's email.
     * @param otp The OTP used in the previous step.
     * @param resetToken The temporary token issued after OTP verification.
     * @param newPassword The new raw password.
     */
    @Override
    @Transactional
    public void resetPassword(String email, String otp, String resetToken, String newPassword) {
        User user = userHelper.validateAndGetUserForAuth(email);
        userHelper.validateUserForSignup(email, newPassword);

        // Final security check: verify that this specific OTP/Token combo was verified and hasn't expired
        boolean valid = resetPasswordObjectRepository
                .findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(user, Instant.now(), otp, UUID.fromString(resetToken))
                .isPresent();

        if (valid) {
            // Update the password using the standard secure encoder
            user.setPassword(passwordEncoder.encode(newPassword));
            user.setTokenVersion(user.getTokenVersion() + 1);
            refreshTokenRepository.revokeAllByUser(user);
            userRepository.save(user);

            // Clean up: delete the reset object immediately after use
            resetPasswordObjectRepository.deleteAllByUser(user);
        } else {
            throw new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid"));
        }
    }

    // ===================================================================================
    // SECTION 5: Internal Token Management (The "Engine")
    // ===================================================================================

    /**
     * <h1>Session Provisioning Engine</h1>
     * 
     * <p>Creates and persists a new Refresh Token entity.</p>
     *
     * <p><b>Behind the Scenes (Hybrid Session):</b>
     * Generates a unique JTI (JWT ID) and links it to the {@link User}. Storing this in 
     * the {@link RefreshTokenRepository} enables precise revocation during logout or 
     * security breaches, turning a stateless JWT into a <b>Hybrid Session</b>.</p>
     *
     * @param user The user for whom the token is generated.
     * @return The persisted {@link RefreshToken} entity.
     */
    @Override
    public RefreshToken createRefreshToken(User user) {
        String refreshTokenJti = UUID.randomUUID().toString();
        return refreshTokenRepository.save(RefreshToken.create(user, refreshTokenJti, jwtService.getRefreshTtlSeconds()));
    }

    /**
     * <h1>Refresh Token Rotation Mechanism</h1>
     * 
     * <p>Implements <b>Refresh Token Rotation</b> to maximize session security.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Revokes the existing token and records the JTI of the token that will replace it.
     * 2. Generates and persists a completely new {@link RefreshToken} entity.
     * 3. Returns the fresh entity.
     * </p>
     *
     * @param oldToken The token currently being rotated.
     * @return A new, unrevoked {@link RefreshToken} entity.
     */
    @Override
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        // 1. Invalidate the old token permanently
        oldToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        oldToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(oldToken);

        // 2. Provision and return a fresh token
        return refreshTokenRepository.save(RefreshToken.create(oldToken.getUser(), newJti, jwtService.getRefreshTtlSeconds()));
    }

    /**
     * <h1>Session Kill-Switch (Revocation)</h1>
     * 
     * <p>Revokes a valid refresh token, permanently invalidating the session.</p>
     * 
     * @param refreshTokenStr The raw JWT string.
     */
    @Override
    @Transactional
    public void revokeRefreshToken(String refreshTokenStr) {
        RefreshToken token = getValidatedRefreshToken(refreshTokenStr);
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    /**
     * <h1>Session Validator</h1>
     * 
     * <p>Validates a Refresh Token string against security policies and database state.</p>
     *
     * @param refreshTokenStr The raw JWT refresh token string.
     * @return The validated {@link RefreshToken} entity.
     */
    @Override
    public RefreshToken getValidatedRefreshToken(String refreshTokenStr) {
        // Parse once to extract claims
        io.jsonwebtoken.Claims claims = jwtService.parse(refreshTokenStr).getPayload();
        String jti = claims.getId();
        UUID userId = UUID.fromString(claims.getSubject());

        // 1. Verify existence in the revocation database
        RefreshToken refreshTokenOb = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("token.refresh.not_found_db")));

        // 2. Critical security checks
        if (refreshTokenOb.isRevoked()) {
            // DETECTED COMPROMISE: "Token Family Revocation" (The Kill Switch)
            // If a revoked token is reused, we assume the whole session family is stolen.
            log.warn("DETECTED COMPROMISE: Revoked token reuse attempt for user: {}. Triggering Kill-Switch.", userId);
            refreshTokenRepository.revokeAllByUser(refreshTokenOb.getUser());
            throw new BadCredentialsException(messageHelper.getMessage("token.refresh.compromised"));
        }
        
        if (refreshTokenOb.getExpiresAt().isBefore(Instant.now())) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.expired"));

        // 3. Ownership check: ensure the token belongs to the user specified in the JWT payload
        if (!refreshTokenOb.getUser().getId().equals(userId)) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.user_mismatch"));

        return refreshTokenOb;
    }

    // ===================================================================================
    // SECTION 6: Web Transport Engine (Protocol Orchestration)
    // ===================================================================================

    /**
     * <h1>Hierarchical Token Extractor</h1>
     * 
     * <p>Extracts a refresh token from the request using a prioritized search strategy 
     * (Cookies first, fallback to JSON body).</p>
     */
    private String extractRefreshToken(RefreshTokenRequest body, HttpServletRequest request) {
        String refreshToken = readRefreshTokenRequest(body, request)
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("token.refresh.not_present")));

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException(messageHelper.getMessage("token.refresh.invalid"));
        }
        return refreshToken;
    }

    /**
     * Internal extraction strategy: Checks Cookies first, then falls back to Request Body.
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
     * <h1>Authentication Response Generator</h1>
     * 
     * <p>Assembles the final API response, injecting security cookies and mapping user entities.</p>
     */
    private TokenResponse generateAuthenticatedResponse(HttpServletResponse response, User user, String accessToken, String refreshToken) {

        // 1. Attach the Refresh Token as a Secure HttpOnly Cookie
        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());

        // 2. Add security headers to prevent token caching in the browser
        cookieService.addNoStoreHeadersToResponse(response);

        // 3. Map User entity to minimalist Auth View for the response body
        AuthUserResponse authUserResponse = AuthUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .image(user.getImage())
                .provider(user.getProvider())
                .roles(user.getRoles().stream()
                        .map(role -> com.substring.authapp.dtos.admin.RoleDto.builder()
                                .id(role.getId())
                                .name(role.getName().name())
                                .build())
                        .collect(java.util.stream.Collectors.toSet()))
                .build();

        // 4. Construct and return the final TokenResponse body
        return TokenResponse.builder()
                .accessToken(accessToken)
                .expiresIn(jwtService.getAccessTtlSeconds())
                .tokenType("Bearer")
                .user(authUserResponse)
                .build();
    }

    /**
     * <h1>Social Authentication Response Generator</h1>
     * 
     * <p>Executes the final security handshake for OAuth2 identities. This method 
     * bridges the gap between external social profiles (Google/GitHub) and internal 
     * stateful sessions by provisioning a new {@link RefreshToken} and injecting 
     * security cookies.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Session Provisioning:</b> Creates a database-backed {@link RefreshToken} entity.
     * 2. <b>Credential Generation:</b> Signs a fresh Refresh JWT containing the JTI.
     * 3. <b>Cookie Injection:</b> Attaches the token as a secure, HttpOnly cookie to the {@link HttpServletResponse}.
     * 4. <b>Header Hardening:</b> Adds Cache-Control directives to prevent token leakage.
     * 5. <b>Access Provisioning:</b> Generates a stateless Access Token for the frontend.
     * </p>
     * 
     * <p><b>Design Rationale (The "Why"):</b>
     * Centralizing this logic here ensures that social login sessions follow the 
     * exact same security policies (TTL, Cookie security, Revocation capability) 
     * as standard password-based logins, achieving <b>Protocol Handshake Symmetry</b>.
     * </p>
     * 
     * @param user The provisioned social user.
     * @param response The HTTP response for cookie injection.
     * @return The generated Access Token string.
     */
    @Override
    public String generateOAuth2AuthenticatedResponse(User user, HttpServletResponse response) {
        RefreshToken refreshTokenOb = createRefreshToken(user);

        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());

        // Handshake Finalization: Inject security cookies directly
        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeadersToResponse(response);

        // Return the Access Token for the frontend handshake
        return jwtService.generateAccessToken(user);
    }

}