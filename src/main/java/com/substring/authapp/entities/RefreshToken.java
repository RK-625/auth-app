package com.substring.authapp.entities;


import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * <h1>Session Persistence Domain Entity</h1>
 *
 * <p>Represents a long-lived Refresh Token used to issue new Access Tokens. This entity 
 * provides the "Stateful" anchor for an otherwise "Stateless" JWT architecture, 
 * enabling session revocation and rotation.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. Generated during the authentication handshake after successful credential verification.
 * 2. Persisted in the {@code refresh_tokens} table with a unique {@code jti} (JWT ID).
 * 3. Validated during the {@code /refresh} flow to verify session legitimacy.
 * 4. Revoked or rotated to maintain a "Zero Trust" security posture.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * Managed by the {@code PersistenceContext}, this entity uses a {@code UUID} strategy for its primary key
 * to ensure globally unique identifiers across distributed systems. It includes database-level indexes
 * on {@code jti} and {@code user_id} to optimize lookup performance during the token refresh handshake.
 * </p>
 *
 * <p><b>Security Integrity:</b>
 * <ul>
 *   <li><b>{@code @Index}:</b> The {@code refresh_token_jti_idx} ensures O(1) lookup during the critical 
 *       refresh path, while {@code unique=true} prevents JTI collision attacks.</li>
 *   <li><b>{@code @Column(updatable = false)}:</b> Applied to {@code jti}, {@code user}, and 
 *       {@code createdAt} to ensure the immutable nature of the session's origin. Once a 
 *       session is bound to a user and JTI, it cannot be re-assigned.</li>
 *   <li><b>{@code revoked}:</b> Acts as a "Kill Switch," allowing immediate termination 
 *       of compromised sessions before the TTL expires.</li>
 * </ul>
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Uses {@link FetchType#LAZY} for the User relationship to prevent unnecessary joins during
 * simple token validation checks. This adheres to the principle of "Fetch Only What You Need"
 * while maintaining a strong foreign key constraint for data integrity.
 * </p>
 */
@Entity
@Table(name = "refresh_tokens",indexes = {
        @Index(name = "refresh_token_jti_idx", columnList = "jti", unique = true),
        @Index(name ="refresh_token_user_id_idx",columnList = "user_id")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    /**
     * Unique identifier for the RefreshToken record.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * The unique JWT ID (JTI) of the refresh token.
     * Used as a unique handle for token revocation and rotation tracking.
     */
    @Column(unique = true,name = "jti",nullable = false,updatable = false)
    private String jti; // this is the refresh toke uuid

    /**
     * The owner of this refresh token.
     * Fetched LAZY to optimize performance during token-only validation.
     */
    @ManyToOne(fetch = FetchType.LAZY,optional = false)
    @JoinColumn(name = "user_id",nullable = false,updatable = false)
    private User user; // the user id the refresh token belongs to

    /**
     * The point in time when this token was issued.
     */
    @Column(updatable = false,nullable = false)
    private Instant createdAt;

    /**
     * The expiration timestamp. After this point, the token is considered invalid by the system.
     */
    @Column(updatable = false,nullable = false)
    private Instant expiresAt;

    /**
     * Flag indicating if this token has been manually or automatically revoked.
     */
    @Column(nullable = false)
    private boolean revoked;

    /**
     * If this token was rotated, this field points to the JTI of the successor token.
     */
    private String replacedByToken;

    /**
     * Factory method to initialize a new RefreshToken instance.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Maps the provided User and JTI to the new instance.
     * 2. Sets the creation timestamp to the current system time.
     * 3. Calculates the expiration time based on the provided TTL (Time-To-Live).
     * 4. Initializes the {@code revoked} state to {@code false}.
     * </p>
     *
     * @param user The {@link User} entity this token belongs to.
     * @param jti The unique JWT ID for this session.
     * @param ttlSeconds The duration in seconds until this token expires.
     * @return A {@link RefreshToken} instance ready for persistence.
     */
    public static RefreshToken create(User user, String jti, long ttlSeconds) {
        return RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                .revoked(false)
                .build();
    }
}
