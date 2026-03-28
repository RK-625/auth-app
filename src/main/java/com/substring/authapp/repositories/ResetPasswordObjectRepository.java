package com.substring.authapp.repositories;

import com.substring.authapp.entities.ResetPasswordObject;
import com.substring.authapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for {@link ResetPasswordObject} entity operations.
 * Manages the persistence of password reset requests, including OTPs and reset tokens.
 */
public interface ResetPasswordObjectRepository extends JpaRepository<ResetPasswordObject, UUID> {

    /**
     * Checks if a valid reset request exists for a given user, OTP, and token.
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
     * @param user The user associated with the reset request.
     * @param otp The OTP provided.
     * @param expiresAt The current time to check against expiration.
     * @return An {@link Optional} containing the reset request if it matches all criteria.
     */
    Optional<ResetPasswordObject> findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(User user, String otp, Instant expiresAt);

    /**
     * Finds any active (non-expired) reset request for a user.
     * 
     * @param user The user to check for an active reset request.
     * @param expiresAt The current time to check against expiration.
     * @return An {@link Optional} containing the reset request if found and still valid.
     */
    Optional<ResetPasswordObject> findByUserAndExpiresAtGreaterThan(User user, Instant expiresAt);

    /**
     * Deletes all reset requests associated with a specific user.
     * Useful for cleanup after a password has been successfully reset.
     * 
     * @param user The user whose reset requests should be removed.
     */
    void deleteAllByUser(User user);

    /**
     * Finds a specific reset request that has been marked as used but matches other criteria.
     * This is used for verification in multi-step password reset flows.
     * 
     * @param user The user associated with the reset request.
     * @param expiresAt The current time to check against expiration.
     * @param otp The OTP provided.
     * @param resetToken The unique token provided.
     * @return An {@link Optional} containing the reset request if it matches all criteria.
     */
    Optional<ResetPasswordObject> findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(User user, Instant expiresAt, String otp, UUID resetToken);
}