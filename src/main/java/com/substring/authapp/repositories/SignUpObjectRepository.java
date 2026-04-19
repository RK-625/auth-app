package com.substring.authapp.repositories;

import com.substring.authapp.entities.SignUpObject;
import com.substring.authapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Registration Staging Repository</h1>
 * 
 * <p>Provides persistence services for the {@link SignUpObject} during the 
 * multi-phase registration handshake. It acts as the gatekeeper for transient 
 * identity state.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Creation:</b> Persists the initial handshake during {@code signUpRequest}.
 * 2. <b>Verification:</b> Facilitates lookup of unexpired records via 
 *    {@code findByEmailAndOtpAndExpiresAtGreaterThan}.
 * 3. <b>Purge:</b> Executes batch deletions of expired records to ensure 
 *    data minimization.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This repository is utilized by the {@link com.substring.authapp.services.impl.AuthServiceImpl} 
 * for business logic and the {@link com.substring.authapp.services.CleanupService} 
 * for background maintenance. The {@link Query} methods are optimized for 
 * high-performance lookups against the {@code email} and {@code expiresAt} indices.</p>
 * 
 * <p><b>Design Rationale (Staging Isolation):</b>
 * Keeping the signup handshake state in a separate table/repository isolates the 
 * primary user table from "Registration Noise" (abandoned attempts). This preserves 
 * index performance and ensures that only verified users are ever provisioned into 
 * the core {@link User} entity.</p>
 */
public interface SignUpObjectRepository extends JpaRepository<SignUpObject, UUID> {
    long deleteByEmail(String email);
    Optional<SignUpObject> findByEmailAndOtpAndExpiresAtGreaterThan(String email, String otp, Instant expiresAt);
    Optional<SignUpObject> findByEmailAndOtpAndExpiresAtGreaterThanAndSignUpToken(String email, String otp, Instant expiresAt, UUID signUpToken);

    Optional<SignUpObject> findByEmail(String email);

    boolean existsByEmailAndOtpAndExpiresAtGreaterThan(String email, String otp, Instant expiresAt);

    boolean existsBySignUpToken(UUID signUpToken);

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