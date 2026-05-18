package com.substring.authapp.entities;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.Instant;
import java.util.UUID;


/**
 * <h1>Password Reset Handshake Domain Entity</h1>
 * 
 * <p>Represents a temporary verification container for the "Forgotten Password" 
 * workflow. It bridges the gap between an unauthenticated request and a 
 * verified credential update.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Initiation:</b> Record created when a user requests a reset, linked 1:1 to {@link User}.
 * 2. <b>Persistence:</b> Managed by the <b>Persistence Context</b> with strict TTL enforcement.
 * 3. <b>Verification:</b> Validates both the {@code resetToken} (URL) and {@code otp} (User Input).
 * 4. <b>Revocation:</b> Flagged as {@code used} immediately upon successful password update.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This entity resides in the <b>Persistence Context</b> to ensure that only one 
 * active reset request exists per user. While it omits <b>Optimistic Locking</b> 
 * ({@code @Version}), the structural <b>Database Constraints</b> act as a 
 * synchronization barrier against concurrent request spam.
 * </p>
 * 
 * <p><b>Database Constraints & Persistence Logic:</b>
 * <ul>
 *   <li><b>Unique User Link:</b> The {@code @OneToOne} mapping with {@link User} 
 *       enforces a <b>Unique Constraint</b>, ensuring that the <b>Persistence Context</b> 
 *       never contains overlapping reset windows for a single identity.</li>
 *   <li><b>Token Handle:</b> The {@code resetToken} column is <b>Unique</b> and 
 *       <b>Non-nullable</b>, serving as the immutable lookup key in the web layer.</li>
 *   <li><b>TTL Indexing:</b> A <b>Database Index</b> ({@code reset_expires_at_idx}) 
 *       is applied to {@code expiresAt} to enable high-speed expiration auditing.</li>
 * </ul>
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * Decoupling the reset state into a separate entity ensures that the primary 
 * {@code User} entity remains free of transient security flags. This enables 
 * aggressive cleanup of stale reset requests without impacting user login 
 * performance or data integrity.
 * </p>
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(indexes = @Index(name = "reset_expires_at_idx", columnList = "expiresAt"))
public class ResetPasswordObject {

    // ===================================================================================
    // SECTION 1: Identity & Handshake State (Fields)
    // ===================================================================================

    /**
     * Unique identifier for the reset request.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * The user requesting the password reset.
     * Fetched EAGERly to ensure user details are immediately available for email 
     * dispatching and verification logic.
     */
    @OneToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(unique = true, nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

    /**
     * One-Time Password (OTP) sent to the user for verification.
     * Security Note: Should be handled as a sensitive credential.
     */
    private String otp;

    /**
     * Unique token sent to the user as part of the password reset link.
     * Acts as the primary handle for identifying the reset request in the web layer.
     */
    @NotNull
    @Column(nullable = false, unique = true)
    private UUID resetToken;

    private boolean used;

    // ===================================================================================
    // SECTION 2: Audit & Lifecycle (Fields)
    // ===================================================================================

    /**
     * Timestamp when the reset request was created.
     */
    private Instant createdAt;

    /**
     * Timestamp when the reset request/OTP expires.
     * Enforced by the business logic to ensure short TTLs.
     */
    private Instant expiresAt;

    /**
     * Tracks the last time an OTP email was dispatched to enforce cooldown periods.
     */
    private Instant lastSentAt;

    /**
     * Optimistic Locking version field.
     * Prevents race conditions during concurrent updates to the reset request.
     */
    @Version
    private Integer version;

    // ===================================================================================
    // SECTION 3: Constructors & Domain Logic
    // ===================================================================================

    /**
     * Constructor for creating a new password reset request.
     * 
     * @param user The {@link User} entity requesting the reset.
     * @param otp The generated OTP for verification.
     * @param resetToken The unique UUID for the reset link handle.
     * @param ttlSeconds The lifespan of the verification code.
     */
    public ResetPasswordObject(User user, String otp, UUID resetToken, long ttlSeconds) {
        this.user = user;
        this.otp = otp;
        this.resetToken = resetToken;
        this.createdAt = Instant.now();
        this.lastSentAt = Instant.now();
        this.expiresAt = Instant.now().plusSeconds(ttlSeconds);
        this.used = false;
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
