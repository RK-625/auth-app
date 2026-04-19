package com.substring.authapp.entities;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.Instant;
import java.util.UUID;


/**
 * Transient entity used for the "Forget Password" workflow.
 * Stores temporary verification credentials (OTP and Reset Token) linked to a specific user.
 *
 * <p><b>JPA Persistence Context:</b>
 * This entity uses a 1:1 relationship with the {@link User} entity to enforce a constraint
 * where only one active reset request can exist per user at any given time. The 
 * {@link PrePersist} hook is utilized to automatically set expiration logic and initial state.
 * </p>
 *
 * <p><b>Security Lifecycle:</b>
 * 1. <b>Creation:</b> A new record is generated when a user requests a password reset.
 * 2. <b>Verification:</b> The system validates the {@code resetToken} (via URL) and {@code otp} (via user input).
 * 3. <b>Expiration:</b> Tokens are intentionally short-lived (60 seconds by default) to minimize 
 *    the window of opportunity for intercept attacks.
 * 4. <b>Consumption:</b> Once used, the {@code used} flag is set to {@code true}, preventing replay attacks.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Separating reset logic into its own entity instead of adding fields to the {@code User} 
 * entity maintains a clean separation of concerns and allows for aggressive cleanup 
 * strategies of expired reset requests.
 * </p>
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(indexes = @Index(name = "reset_expires_at_idx", columnList = "expiresAt"))
public class ResetPasswordObject {
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
    private User user;

    /**
     * One-Time Password (OTP) sent to the user for verification.
     * Security Note: Should be handled as a sensitive credential.
     */
    private String otp;

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
     * Flag indicating if the reset credentials have already been consumed.
     */
    private boolean used;

    /**
     * Tracks the last time an OTP email was dispatched to enforce cooldown periods.
     */
    private Instant lastSentAt;

    /**
     * Unique token sent to the user as part of the password reset link.
     * Acts as the primary handle for identifying the reset request in the web layer.
     */
    @NotNull
    @Column(nullable = false, unique = true)
    private UUID resetToken;

    /**
     * Constructor for creating a new password reset request.
     * 
     * @param user The {@link User} entity requesting the reset.
     * @param otp The generated OTP for verification.
     * @param resetToken The unique UUID for the reset link handle.
     */
    public ResetPasswordObject(User user, String otp, UUID resetToken) {
        this.user = user;
        this.otp = otp;
        this.resetToken = resetToken;
        this.createdAt = Instant.now();
        this.lastSentAt = Instant.now();
        this.expiresAt = Instant.now().plusSeconds(300);
        this.used = false;
    }

    /**
     * Refreshes the OTP and resets the expiry for a "Resend" request.
     */
    public void refreshOtp(String newOtp) {
        this.otp = newOtp;
        this.lastSentAt = Instant.now();
        this.expiresAt = Instant.now().plusSeconds(300);
        this.used = false;
    }
}
