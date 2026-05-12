package com.substring.authapp.repositories;

import com.substring.authapp.entities.SignUpObject;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Registration Staging Data Access Provider</h1>
 * 
 * <p>Provides persistence services for the {@link SignUpObject} during the 
 * multi-phase registration handshake. It acts as the gatekeeper for transient 
 * identity state.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Staging:</b> Persists the initial handshake during {@code signUpRequest}.
 * 2. <b>Verification:</b> Facilitates lookup of unexpired records via derived queries.
 * 3. <b>Cleanup:</b> Executes batch deletions of expired records via {@code deleteByExpiresAtBefore}.
 * 4. <b>Proxying:</b> Leverages Spring Data's proxy implementation for boilerplate CRUD.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This repository utilizes <b>Spring Data JPA Proxy Generation</b> to manage 
 * transient registration state. The <b>@Index optimizations</b> on the {@code expiresAt} 
 * column (defined in {@link SignUpObject}) are specifically designed to optimize 
 * <b>Background Cleanup Tasks</b>. Without this index, the hourly purge of stale 
 * records would result in a full table scan, potentially locking the staging 
 * table during high-traffic registration periods.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * Keeping the signup handshake state in a separate table/repository isolates the 
 * primary user table from "Registration Noise." The <b>Index-Driven Cleanup</b> 
 * strategy ensures that the system remains "Fail-Fast" and self-cleaning, 
 * maintaining optimal performance for new registration attempts.
 * </p>
 */
public interface SignUpObjectRepository extends JpaRepository<SignUpObject, UUID> {

    // ===================================================================================
    // SECTION 1: Handshake Discovery & Validation
    // ===================================================================================

    /**
     * Finds a signup request by email.
     * 
     * @param email The user's candidate email.
     * @return An {@link Optional} containing the staging record.
     */
    Optional<SignUpObject> findByEmail(String email);

    /**
     * Validates an OTP against a specific email and expiration window.
     * 
     * @param email User email.
     * @param otp Verification code.
     * @param expiresAt Expiration boundary.
     * @return An {@link Optional} containing the record if valid.
     */
    Optional<SignUpObject> findByEmailAndOtpAndExpiresAtGreaterThan(String email, String otp, Instant expiresAt);

    /**
     * Validates the terminal phase of the registration handshake.
     * 
     * @param email User email.
     * @param otp Verification code.
     * @param expiresAt Expiration boundary.
     * @param signUpToken Secure UUID issued in Phase 2.
     * @return An {@link Optional} containing the record if valid.
     */
    Optional<SignUpObject> findByEmailAndOtpAndExpiresAtGreaterThanAndSignUpToken(String email, String otp, Instant expiresAt, UUID signUpToken);

    /**
     * Predicate check for active OTPs.
     * 
     * @param email User email.
     * @param otp Verification code.
     * @param expiresAt Expiration boundary.
     * @return true if an active OTP exists.
     */
    boolean existsByEmailAndOtpAndExpiresAtGreaterThan(String email, String otp, Instant expiresAt);

    /**
     * Predicate check for token validity.
     * 
     * @param signUpToken Secure UUID.
     * @return true if the token is known.
     */
    boolean existsBySignUpToken(UUID signUpToken);

    // ===================================================================================
    // SECTION 2: Lifecycle & Cleanup Operations
    // ===================================================================================

    /**
     * Atomic removal of a staging record by email.
     * 
     * @param email The target email.
     * @return Number of records deleted.
     */
    long deleteByEmail(String email);

    /**
     * <h1>Stale Record Purge</h1>
     * 
     * <p>Executes a bulk deletion of all {@link SignUpObject} records that have 
     * exceeded their time-to-live.</p>
     * 
     * <p><b>Design Rationale:</b>
     * This method prevents "Data Rot" in the staging table. It is triggered by 
     * the {@code CleanupService} on a recurring schedule to reclaim storage 
     * space and maintain optimal index depth for new signup attempts.</p>
     * 
     * @param now The current point in time.
     */
    void deleteByExpiresAtBefore(Instant now);
}