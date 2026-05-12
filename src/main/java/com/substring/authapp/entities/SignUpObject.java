package com.substring.authapp.entities;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * <h1>Registration Handshake Staging Object</h1>
 * 
 * <p>Represents a temporary, stateful entity used to verify email ownership before 
 * formal account creation. It acts as a "Limbo" state container that manages the 
 * lifecycle of One-Time Passwords (OTP) and secondary verification tokens.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Initiation:</b> Created during {@code signUpRequest} with a 5-minute TTL.
 * 2. <b>Verification:</b> Transitions to a 'verified' state (used=true) upon OTP submission.
 * 3. <b>Handshake:</b> Managed by the <b>Persistence Context</b> during the verification phase.
 * 4. <b>Conversion:</b> Converted to a permanent {@link User} entity upon final step completion.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This entity is managed within the <b>Persistence Context</b> to track registration 
 * state across multiple requests. It utilizes <b>Optimistic Locking</b> via the 
 * {@code @Version} field to prevent race conditions during high-frequency 
 * "Resend OTP" requests. Security is maintained through a combination of 
 * <b>Database Constraints</b> and transient memory management.
 * </p>
 * 
 * <p><b>Database Constraints & Persistence Logic:</b>
 * <ul>
 *   <li><b>Unique Handle:</b> The {@code email} and {@code signUpToken} columns 
 *       carry <b>Unique Constraints</b> to ensure one registration flow per user.</li>
 *   <li><b>TTL Index:</b> A <b>Database Index</b> ({@code signup_expires_at_idx}) 
 *       is applied to {@code expiresAt} to facilitate efficient cleanup of stale 
 *       records from the <b>Persistence Context</b>.</li>
 *   <li><b>Stateless Secrets:</b> The {@code password} field is marked as 
 *       {@link Transient}. This is a critical <b>Security Purpose</b>: it allows 
 *       the plain-text password to be carried in-memory during the multi-step 
 *       handshake without ever persisting it to the staging table, mitigating 
 *       <b>Data Exposure</b> risks in temporary logs or snapshots.</li>
 * </ul>
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * By using a staging table instead of a 'disabled' user, we preserve the purity of 
 * the {@code users} table. The **Optimistic Locking** strategy ensures that 
 * concurrent verification attempts do not result in stale state transitions, 
 * maintaining the integrity of the registration lifecycle.
 * </p>
 */
@Getter
@Setter
@Entity
@NoArgsConstructor
@Table(indexes = @Index(name = "signup_expires_at_idx", columnList = "expiresAt"))
public class SignUpObject {

    // ===================================================================================
    // SECTION 1: Identity & Handshake State (Fields)
    // ===================================================================================

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String otp;

    private boolean used;

    /**
     * Secondary verification token issued after OTP success.
     */
    @NotNull
    @Column(nullable = false, unique = true)
    private UUID signUpToken;

    // ===================================================================================
    // SECTION 2: Audit & Lifecycle (Fields)
    // ===================================================================================

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant expiresAt;

    /**
     * Tracks the last time an OTP email was dispatched to enforce cooldown periods.
     */
    private Instant lastSentAt;

    /**
     * <b>Optimistic Locking Mechanism:</b>
     * Ensures that concurrent updates to the same signup request (e.g., rapid 
     * Resend OTP clicks) do not overwrite each other. Managed by Hibernate's 
     * <b>Persistence Context</b>.
     */
    @Version
    private Long version;

    // ===================================================================================
    // SECTION 3: Transient Handshake State
    // ===================================================================================

    /**
     * <b>Stateless Handshake Holder:</b>
     * This field is marked as {@code @Transient} to prevent persistence. It allows 
     * the password to be carried from Phase 1 (Initiate) through Phase 3 (Complete) 
     * within the object lifecycle, but ensures it is never saved to the 
     * temporary {@code signup_object} table.
     */
    @Transient
    private String password;

    // ===================================================================================
    // SECTION 4: Constructors & Domain Logic
    // ===================================================================================

    public SignUpObject(String email, String otp, UUID signUpToken, long ttlSeconds) {
        this.email = email;
        this.otp = otp;
        this.signUpToken = signUpToken;
        this.createdAt = Instant.now();
        this.lastSentAt = Instant.now();
        this.expiresAt = Instant.now().plusSeconds(ttlSeconds);
    }

    /**
     * Refreshes the OTP and resets the expiry for a "Resend" request.
     * 
     * @param newOtp The fresh verification code.
     * @param ttlSeconds The lifespan of the new code.
     */
    public void refreshOtp(String newOtp, long ttlSeconds) {
        this.otp = newOtp;
        this.lastSentAt = Instant.now();
        this.expiresAt = Instant.now().plusSeconds(ttlSeconds);
        this.used = false;
    }
}
