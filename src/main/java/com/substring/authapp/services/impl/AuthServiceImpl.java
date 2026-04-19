package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.SignUpObjectDto;
import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.*;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.*;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.services.EmailService;
import com.substring.authapp.services.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import com.substring.authapp.helpers.MessageHelper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
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
 * 2. <b>Credential Orchestration:</b> Manages the creation and rotation of JWTs and Refresh Tokens.
 * 3. <b>Account Recovery:</b> Coordinates the secure, multi-step password reset lifecycle.
 * </p>
 *
 * <p><b>Behind the Scenes (The Bean Handshake):</b>
 * This service interacts with multiple Spring-managed beans to fulfill the security contract:
 * <ul>
 *   <li>{@link PasswordEncoder}: Utilizes {@code BCryptPasswordEncoder} for one-way, salted password hashing.</li>
 *   <li>{@link JwtService}: Manages the cryptographic signing and parsing of stateless JSON Web Tokens.</li>
 *   <li>{@link UserRepository}: Executes JPA queries to manage {@link User} entities.</li>
 * </ul>
 * It also manages {@link RefreshToken} and {@link ResetPasswordObject} entities, 
 * enforcing transactional boundaries via {@link Transactional} to ensure data integrity.
 * </p>
 *
 * <p><b>Design Rationale (Stateful Statelessness):</b>
 * While the Access JWT is stateless for performance, this service maintains a database-backed 
 * {@link RefreshToken} record. This creates a <b>"Kill-Switch"</b> capability: by revoking 
 * the refresh token in the database, the system can instantly terminate a user's session 
 * (Hybrid Session) without waiting for the JWT to expire.
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.services.AuthService
 * @see com.substring.authapp.security.JwtService
 * @see com.substring.authapp.helpers.UserHelper
 */
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final UserHelper userHelper;
    private final MessageHelper messageHelper;
    private final RoleRepository roleRepository;
    private final SignUpObjectRepository signUpObjectRepository;
    private final ResetPasswordObjectRepository resetPasswordObjectRepository;
    private final EmailService emailService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    /**
     * <h1>Signup Orchestration Engine (Phase 1: Initiation)</h1>
     * 
     * <p>Initiates the multi-step user registration handshake. This method implements 
     * the <b>Deferred Provisioning</b> pattern by creating a temporary {@link SignUpObject} 
     * instead of a full {@link User} entity, preventing unverified accounts from 
     * polluting the primary identity table. Password collection is deferred to Phase 3.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Validation:</b> Verifies email uniqueness via {@link UserHelper}.
     * 2. <b>Upsert Logic:</b>
     *    - If an active signup exists, it refreshes the OTP and resets the 5-minute expiry.
     *    - If not, it generates new unique credentials and persists a fresh record.
     * 3. <b>Notification:</b> Dispatches the verification code via {@link EmailService}.
     * </p>
     * 
     * <p><b>Behind the Scenes (Component Interaction):</b>
     * Uses an <b>Upsert</b> pattern to minimize database round-trips. It leverages 
     * the {@link SignUpObjectRepository} for persistence. Password processing is 
     * skipped in this phase as the frontend only enables the password field after 
     * successful OTP verification.</p>
     * 
     * <p><b>Design Rationale (Limbo State):</b>
     * By refreshing the existing object instead of deleting/re-creating, we maintain 
     * database consistency. The 5-minute initial TTL accounts for potential 
     * latencies in global email delivery while ensuring the 'Limbo' state is 
     * strictly time-bound.</p>
     * 
     * @param signUpObjectDto DTO containing the candidate user's email.
     */
    @Override
    @Transactional
    public void signUpRequest(SignUpObjectDto signUpObjectDto) {
        validateSignUpEmail(signUpObjectDto.getEmail());
        
        Optional<SignUpObject> signUpObjectOpt = signUpObjectRepository.findByEmail(signUpObjectDto.getEmail());
        
        String finalOtp;
        if (signUpObjectOpt.isPresent()) {
            SignUpObject existing = signUpObjectOpt.get();
            
            // COOLDOWN CHECK: Prevent spamming (60 seconds)
            if (existing.getLastSentAt().plusSeconds(60).isAfter(Instant.now())) {
                throw new BadCredentialsException(messageHelper.getMessage("auth.otp.cooldown"));
            }

            var newKeys = userHelper.generateUniqueHandshakeKeys(keys -> 
                signUpObjectRepository.existsByEmailAndOtpAndExpiresAtGreaterThan(signUpObjectDto.getEmail(), keys.getFirst(), Instant.now())
            );
            existing.refreshOtp(newKeys.getFirst());
            finalOtp = newKeys.getFirst();
            signUpObjectRepository.save(existing);
        } else {
            // Use Generic Factory for new requests
            var keys = userHelper.generateUniqueHandshakeKeys(k -> false); // New record for this email
            SignUpObject newSignup = new SignUpObject(signUpObjectDto.getEmail(), keys.getFirst(), keys.getSecond());
            signUpObjectRepository.save(newSignup);
            finalOtp = keys.getFirst();
        }
        
        emailService.sendSignUpOtp(signUpObjectDto.getEmail(), finalOtp);
    }

    /**
     * <h1>Signup Orchestration Engine (Phase 2: OTP Verification)</h1>
     * 
     * <p>Validates the user's possession of the verification code and transitions 
     * the handshake to its terminal phase. This step triggers the <b>Two-Phase Expiry</b> 
     * contraction to minimize the security window.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Discovery:</b> Locates an unexpired record matching the email and OTP.
     * 2. <b>State Transition:</b> Marks the object as {@code used} and reduces the 
     *    expiry window to a 60-second grace period (Phase-2 Expiry).
     * 3. <b>Authorization:</b> Returns the UUID {@code signUpToken} as proof of verification.
     * </p>
     * 
     * <p><b>Behind the Scenes (Cleanup Interaction):</b>
     * By setting a 60-second expiry, we ensure that even if the user abandons the 
     * process at Phase 3, the {@link com.substring.authapp.services.CleanupService} 
     * will identify and purge this record in its next cycle, maintaining a lean 
     * staging table.</p>
     * 
     * @param email The target user email.
     * @param otp The 6-digit verification code.
     * @return A secure UUID string used for Phase 3.
     * @throws BadCredentialsException If the OTP is invalid or expired.
     */
    @Override
    @Transactional
    public String verifySignUpOtp(String email ,String otp){
        validateSignUpEmail(email);
        SignUpObject signUpObject = signUpObjectRepository
                .findByEmailAndOtpAndExpiresAtGreaterThan(email, otp, Instant.now())
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid")));
        
        // Mandatory state transition for security
        signUpObject.setExpiresAt(Instant.now().plusSeconds(60));
        signUpObject.setUsed(true);
        signUpObjectRepository.save(signUpObject);
        
        return signUpObject.getSignUpToken().toString();
    }


    /**
     * <h1>Signup Orchestration Engine (Phase 3: Final Provisioning)</h1>
     * 
     * <p>The terminal point of the <b>Deferred Provisioning</b> handshake. Converts 
     * the verified signup state into a permanent user identity and performs 
     * immediate cleanup of the staging record.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Pre-Creation Validation:</b> Verifies the password strength one last time.
     * 2. <b>Integrity Check:</b> Ensures the email, OTP, and Token match a record 
     *    that was successfully <b>Verified</b> (used=true) and is within the 60s window.
     * 3. <b>Provisioning:</b> Triggers {@link UserHelper#buildAndSaveUser} to persist 
     *     the {@link User} entity.
     * 4. <b>Atomic Cleanup:</b> Deletes the {@link SignUpObject} immediately 
     *    upon success to prevent token replay.
     * </p>
     * 
     * <p><b>Behind the Scenes (Component Interaction):</b>
     * This method is the "Success Path" for cleanup. While the 
     * {@link com.substring.authapp.services.CleanupService} handles abandonment, 
     * this method ensures that successful registrations are cleaned up <b>Real-Time</b> 
     * within the same database transaction.</p>
     * 
     * <p><b>Design Rationale:</b>
     * By requiring {@code used == true}, this method enforces strict state 
     * transition ordering, ensuring that Phase 2 cannot be bypassed even if a 
     * malicious actor predicts a UUID token.</p>
     * 
     * @param email User email.
     * @param otp OTP used in Phase 2.
     * @param signUpToken UUID token issued in Phase 2.
     * @param password The raw password for the new account.
     */
    @Override
    @Transactional
    public void verifySignUpToken(String email, String otp, String signUpToken, String password) {
        userHelper.validateUserForSignup(email, password); 
        
        // Critical: Check for used=true to prevent Phase 2 bypass
        SignUpObject validObject = signUpObjectRepository
                .findByEmailAndOtpAndExpiresAtGreaterThanAndSignUpToken(email, otp, Instant.now(), UUID.fromString(signUpToken))
                .filter(SignUpObject::isUsed) // Enforce that OTP was verified
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("signup.validation.failure")));

        // Execute atomic account creation
        UserDto userDto = UserDto.builder().email(email).password(password).build();
        userHelper.buildAndSaveUser(userDto, Provider.LOCAL, UserRole.ROLE_USER);
        
        // Atomic cleanup
        signUpObjectRepository.delete(validObject);
    }

    /**
     * Initiates the password recovery lifecycle.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Verifies user existence via {@link UserRepository}.
     * 2. Checks for existing, unexpired OTPs to prevent spamming and enforce rate limiting.
     * 3. If no active OTP exists, generates a new cryptographically secure OTP and reset token.
     * 4. Persists the {@link ResetPasswordObject} and dispatches an email via {@link EmailService}.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * This method is marked {@link Transactional}, triggering a <b>Spring AOP Proxy</b> that 
     * manages the database transaction. It ensures that the deletion of stale reset 
     * objects and the persistence of the new one are performed atomically.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Uses a <b>Short-Lived OTP</b> (One-Time Password) pattern to minimize the window 
     * of opportunity for brute-force attacks. Reusing an active OTP prevents "email bombing" 
     * and reduces load on the mail server.
     * </p>
     *
     * @param email The user's email address.
     */
    @Override
    @Transactional
    public void initiatePasswordReset(String email) {
        User user = validateEmailAndGetUser(email);
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
            existing.refreshOtp(newKeys.getFirst());
            resetPasswordObjectRepository.save(existing);
            emailService.sendPassWordResetOtp(user.getEmail(), newKeys.getFirst());
        } else {
            resetPasswordObjectRepository.deleteAllByUser(user);
            
            // Use Generic Factory for new requests
            var keys = userHelper.generateUniqueHandshakeKeys(k -> 
                resetPasswordObjectRepository.existsByUserAndOtpAndResetToken(user, k.getFirst(), k.getSecond())
            );
            
            ResetPasswordObject resetPasswordObject = new ResetPasswordObject(user, keys.getFirst(), keys.getSecond());
            resetPasswordObjectRepository.save(resetPasswordObject);
            emailService.sendPassWordResetOtp(user.getEmail(), keys.getFirst());
        }
    }

    /**
     * Validates a password reset OTP and issues a temporary authorization token.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Searches for an unexpired, unused OTP matching the user and input.
     * 2. Marks the OTP as 'used' to prevent replay attacks.
     * 3. Extends the expiration of the associated {@link ResetPasswordObject} by a short 
     *    grace period (60 seconds) to allow for the final password submission.
     * 4. Returns the UUID reset token string as a proof-of-verification.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * Leveraging JPA's <b>Dirty Checking</b>, the status of the {@code used} flag is 
     * automatically synchronized with the database upon transaction commit, without 
     * requiring an explicit {@code save()} call (though one is provided for clarity).
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Separating OTP verification from password updating (two-step process) ensures that 
     * the new password is only accepted after the user has demonstrated control over 
     * their email account, mitigating unauthorized account takeovers.
     * </p>
     *
     * @param email The user's email.
     * @param otp The 6-digit OTP code.
     * @return A secure reset token string.
     * @throws BadCredentialsException If the OTP is invalid, expired, or already used.
     */
    @Override
    @Transactional
    public String verifyPasswordResetOtp(String email, String otp) {
        User user = validateEmailAndGetUser(email);
        
        ResetPasswordObject resetPasswordObject = resetPasswordObjectRepository
                .findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(user, otp, Instant.now())
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid")));
        
        // Mark OTP as verified/used
        resetPasswordObject.setUsed(true);
        // Provide a 60-second grace period for the client to submit the new password
        resetPasswordObject.setExpiresAt(Instant.now().plusSeconds(60));
        resetPasswordObjectRepository.save(resetPasswordObject);
        
        return resetPasswordObject.getResetToken().toString();
    }

    /**
     * Updates a user's password using a verified reset token.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates that the provided email, OTP, and reset token match a 'used' but unexpired record.
     * 2. Hashes the new password and updates the {@link User} entity.
     * 3. Purges all reset-related records for the user to ensure a clean state and prevent token reuse.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * The transaction ensures that the password update and the cleanup of the reset 
     * token are atomic. If the password update fails, the reset token remains valid 
     * for the duration of the grace period.
     * </p>
     *
     * @param email The user's email.
     * @param otp The OTP used in the previous step.
     * @param resetToken The temporary token issued after OTP verification.
     * @param newPassword The new raw password.
     */
    @Override
    @Transactional
    public void resetPassword(String email, String otp, String resetToken, String newPassword) {
        User user = validateEmailAndGetUser(email);
        
        // Final security check: verify that this specific OTP/Token combo was verified and hasn't expired
        boolean valid = resetPasswordObjectRepository
                .findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(user, Instant.now(), otp, UUID.fromString(resetToken))
                .isPresent();
        
        if (valid) {
            // Update the password using the standard secure encoder
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            
            // Clean up: delete the reset object immediately after use
            resetPasswordObjectRepository.deleteAllByUser(user);
        } else {
            throw new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid"));
        }
    }

    /**
     * Creates and persists a new Refresh Token entity.
     *
     * <p><b>Behind the Scenes:</b>
     * Generates a unique JTI (JWT ID) and links it to the {@link User}. Storing this in 
     * the {@link RefreshTokenRepository} allows for stateful management of stateless 
     * JWT sessions, enabling precise revocation during logout or security breaches.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * By persisting the token handle (JTI) rather than the token string itself, we 
     * minimize storage requirements and avoid storing sensitive cryptographic payloads 
     * in the database.
     * </p>
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
     * Implements <b>Refresh Token Rotation</b>.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Revokes the existing token and records the JTI of the token that will replace it.
     * 2. Generates and persists a completely new {@link RefreshToken} entity.
     * 3. Returns the fresh entity.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Rotation ensures that every refresh operation yields a one-time-use token. This 
     * significantly reduces the risk of stolen tokens being used for persistent access 
     * and allows the system to detect reuse attempts (potential breaches).
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
     * Validates a Refresh Token string against security policies and database state.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Parses the JWT to extract the JTI and subject (user ID).
     * 2. Retrieves the corresponding entity from the {@link RefreshTokenRepository}.
     * 3. Enforces checks for revocation, expiration, and user ownership.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * This method bridges the stateless JWT (validated via {@link JwtService}) with the 
     * stateful revocation list. The database lookup uses the indexed {@code jti} field 
     * for O(1) performance.
     * </p>
     *
     * @param refreshTokenStr The raw JWT refresh token string.
     * @return The validated {@link RefreshToken} entity.
     * @throws BadCredentialsException If the token is unknown, revoked, expired, or belongs to another user.
     */
    @Override
    public RefreshToken getValidatedRefreshToken(String refreshTokenStr) {
        // Parse once to extract claims (Performance optimization)
        io.jsonwebtoken.Claims claims = jwtService.parse(refreshTokenStr).getPayload();
        String jti = claims.getId();
        UUID userId = UUID.fromString(claims.getSubject());
        
        // 1. Verify existence in the revocation database
        RefreshToken refreshTokenOb = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("token.refresh.not_found_db")));
                
        // 2. Critical security checks
        if (refreshTokenOb.isRevoked()) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.revoked"));
        if (refreshTokenOb.getExpiresAt().isBefore(Instant.now())) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.expired"));
        
        // 3. Ownership check: ensure the token belongs to the user specified in the JWT payload
        if (!refreshTokenOb.getUser().getId().equals(userId)) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.user_mismatch"));
        
        return refreshTokenOb;
    }

    /**
     * Helper to retrieve a user by email with standardized authentication error handling.
     */
    private User validateEmailAndGetUser(String email) {
        return userHelper.findUserByEmailOrThrow(
            email, 
            new BadCredentialsException(messageHelper.getMessage("auth.forget.email_not_found"))
        );
    }

    private void validateSignUpEmail(String email){
        userHelper.validateSignUpEmail(email);
        return;
    }
}