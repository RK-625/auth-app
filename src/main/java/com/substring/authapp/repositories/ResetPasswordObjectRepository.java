package com.substring.authapp.repositories;

import com.substring.authapp.entities.ResetPasswordObject;
import com.substring.authapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Account Recovery Persistence Provider</h1>
 *
 * <p>Data Access Object (DAO) for managing the lifecycle of {@link ResetPasswordObject} entities. 
 * This repository is the core persistence component for the password recovery system, 
 * managing the ephemeral state of OTPs and secure reset tokens.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Creation:</b> Persists new reset requests with cryptographically secure tokens.
 * 2. <b>Verification:</b> Facilitates multi-parameter lookups to validate user identity.
 * 3. <b>Invalidation:</b> Purges stale or used requests to ensure security integrity.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * Powered by a Spring Data JPA proxy, this interface uses <b>Method Name Derivation</b> 
 * to generate complex boolean and optional queries. It leverages the underlying 
 * {@code EntityManager} to manage the transition of reset objects through their 
 * short-lived persistent lifecycle.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * By isolating the password reset state into a dedicated entity and repository, 
 * we avoid cluttering the primary {@link com.substring.authapp.entities.User} entity 
 * with ephemeral security fields. This ensures a clean separation of concerns 
 * and allows for specific indexing on reset-related columns.
 * </p>
 * 
 * @author Gemini CLI
 * @see com.substring.authapp.entities.ResetPasswordObject
 */
public interface ResetPasswordObjectRepository extends JpaRepository<ResetPasswordObject, UUID> {

    /**
     * Checks for the existence of a specific credential set.
     * 
     * <p><b>Implementation Workflow:</b>
     * Generates an {@code EXISTS} query matching the user, OTP, and reset token. 
     * This is used as a final guard before allowing a password update.
     * </p>
     * 
     * @param user The user associated with the reset request.
     * @param otp The One-Time Password provided by the user.
     * @param resetToken The unique token provided in the reset link.
     * @return true if a matching request exists, false otherwise.
     */
    boolean existsByUserAndOtpAndResetToken(User user, String otp, UUID resetToken);

    /**
     * Finds an unused, non-expired reset request for a user with a specific OTP.
     * 
     * <p><b>Implementation Workflow:</b>
     * Generates a query with a composite {@code WHERE} clause: 
     * {@code user_id = ? AND otp = ? AND used = false AND expires_at >= ?}.
     * </p>
     * 
     * @param user The user associated with the reset request.
     * @param otp The OTP provided.
     * @param expiresAt The current time to check against expiration.
     * @return An {@link Optional} containing the reset request if it matches all criteria.
     */
    Optional<ResetPasswordObject> findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(User user, String otp, Instant expiresAt);

    /**
     * Finds any active (non-expired) reset request for a user.
     * 
     * <p><b>Design Rationale:</b>
     * Used for rate-limiting and duplicate-prevention logic in the service layer. 
     * If an unexpired request already exists, the system can choose to reuse 
     * it rather than generating a new one.
     * </p>
     * 
     * @param user The user to check for an active reset request.
     * @param expiresAt The current time to check against expiration.
     * @return An {@link Optional} containing the reset request if found and still valid.
     */
    Optional<ResetPasswordObject> findByUserAndExpiresAtGreaterThan(User user, Instant expiresAt);

    /**
     * Deletes all reset requests associated with a specific user.
     * 
     * <p><b>Behind the Scenes:</b>
     * This derived delete method is transactional by default. It generates a 
     * {@code DELETE FROM reset_password_objects WHERE user_id = ?} query, 
     * ensuring a clean security state after a successful password change.
     * </p>
     * 
     * @param user The user whose reset requests should be removed.
     */
    void deleteAllByUser(User user);

    /**
     * Finds a specific reset request that has been marked as used but matches other criteria.
     * 
     * <p><b>Implementation Workflow:</b>
     * Used in the final step of the reset flow to ensure that the token being 
     * presented corresponds to an OTP that was previously verified.
     * </p>
     * 
     * @param user The user associated with the reset request.
     * @param expiresAt The current time to check against expiration.
     * @param otp The OTP provided.
     * @param resetToken The unique token provided.
     * @return An {@link Optional} containing the reset request if it matches all criteria.
     */
    Optional<ResetPasswordObject> findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(User user, Instant expiresAt, String otp, UUID resetToken);

    /**
     * Purges all reset handshake objects that have exceeded their time-to-live.
     * 
     * @param now The current point in time.
     */
    void deleteByExpiresAtBefore(Instant now);
}