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
 * 2. <b>Verification:</b> Upon valid OTP submission, the entity transitions to a 
 *    'verified' state (used=true).
 * 3. <b>Phase-2 Expiry:</b> The expiration window is aggressively narrowed to 60 
 *    seconds after OTP verification to minimize the window for token theft.
 * 4. <b>Conversion/Purge:</b> Converted to a {@link User} entity in Phase 3 or 
 *    purged by the {@code CleanupService} if abandoned.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This entity is managed by the {@link com.substring.authapp.repositories.SignUpObjectRepository}. 
 * It utilizes <b>Optimistic Locking</b> via the {@link Version} field to prevent 
 * race conditions during high-frequency "Resend OTP" requests. The {@link Transient} 
 * password field allows the DTO to carry credentials through the handshake without 
 * persisting sensitive data in the staging table.</p>
 * 
 * <p><b>Design Rationale (Deferred Provisioning):</b>
 * By using a staging table instead of creating a 'disabled' user, we ensure that the 
 * primary {@code users} table remains clean and indexed only with verified accounts. 
 * The <b>Two-Phase Expiry</b> model (300s -> 60s) balances user experience (allowing 
 * time for email delivery) with high-security requirements for the final token 
 * exchange.</p>
 */
@Getter
@Setter
@Entity
@NoArgsConstructor
@Table(indexes = @Index(name = "signup_expires_at_idx", columnList = "expiresAt"))
public class SignUpObject {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String otp;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant expiresAt;

    /**
     * Tracks the last time an OTP email was dispatched to enforce cooldown periods.
     */
    private Instant lastSentAt;

    private boolean used;

    /**
     * Secondary verification token issued after OTP success.
     */
    @NotNull
    @Column(nullable = false, unique = true)
    private UUID signUpToken;

    /**
     * Concurrency control for high-frequency signup attempts.
     */
    @Version
    private Long version;

    /**
     * Temporary holder for credentials during the signup handshake.
     * 
     * <p><b>Security Logic: @Transient (Stateless Handshake)</b></p>
     * <p>This field is purposefully <b>not persisted</b> to the database. It allows 
     * the DTO to carry the password through the initial steps for validation, but 
     * ensures that the temporary signup table never stores sensitive credentials. 
     * The password must be provided in the final verification step to be 
     * hashed and saved to the permanent User entity.</p>
     */
    @Transient
    private String password;

    public SignUpObject(String email, String otp, UUID signUpToken) {
        this.email = email;
        this.otp = otp;
        this.signUpToken = signUpToken;
        this.createdAt = Instant.now();
        this.lastSentAt = Instant.now();
        this.expiresAt = Instant.now().plusSeconds(300); // 5 Minutes for initial delivery
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
