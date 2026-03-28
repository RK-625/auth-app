package com.substring.authapp.entities;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.Instant;
import java.util.UUID;


/**
 * Entity used for tracking password reset requests.
 * Stores a temporary token and OTP for a specific user to authorize password changes.
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
public class ResetPasswordObject {
    /**
     * Unique identifier for the reset request.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * The user requesting the password reset.
     * One-to-one relationship ensures only one active reset request per user.
     */
    @OneToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(unique = true, nullable = false)
    private User user;

    /**
     * One-Time Password (OTP) sent to the user for verification.
     */
    private String otp;

    /**
     * Timestamp when the reset request was created.
     */
    private Instant createdAt;

    /**
     * Timestamp when the reset request/OTP expires.
     */
    private Instant expiresAt;

    /**
     * Indicates whether the reset request has already been used.
     */
    private boolean used;

    /**
     * Unique token sent to the user as part of the password reset link.
     */
    @NotNull
    @Column(nullable = false, unique = true)
    private UUID resetToken;

    /**
     * Constructor for creating a new password reset request.
     * 
     * @param user The user requesting the reset.
     * @param otp The OTP for verification.
     * @param resetToken The unique token for the reset link.
     */
    public ResetPasswordObject(User user, String otp, UUID resetToken) {
        this.user = user;
        this.otp = otp;
        this.resetToken = resetToken;
    }

    /**
     * Sets initial values before the entity is persisted.
     * Defaults expiration to 60 seconds (1 minute) after creation.
     */
    @PrePersist
    public void prePersist() {
        createdAt = Instant.now();
        expiresAt = Instant.now().plusSeconds(60); // Security Note: Short lifespan for reset tokens.
        used = false;
    }
}
