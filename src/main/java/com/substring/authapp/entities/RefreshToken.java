package com.substring.authapp.entities;


import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

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
 * 1. <b>Generation:</b> Created during the authentication handshake after credential verification.
 * 2. <b>Persistence:</b> Managed by the <b>Persistence Context</b> and stored in {@code refresh_tokens}.
 * 3. <b>Validation:</b> Checked during the {@code /refresh} flow to verify session legitimacy.
 * 4. <b>Revocation:</b> Flagged as {@code revoked} to terminate compromised sessions.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This entity is managed within the <b>Persistence Context</b>, ensuring that token 
 * revocation is atomic and visible across all nodes. It utilizes <b>Optimistic Locking</b> 
 * (via the {@code version} field) to prevent race conditions during concurrent 
 * token rotation, and enforces integrity via multi-column <b>Database Constraints</b>.
 * </p>
 *
 * <p><b>Database Constraints & Persistence Logic:</b>
 * <ul>
 *   <li><b>Unique Handle:</b> The {@code jti} (JWT ID) column carries a <b>Unique Constraint</b> 
 *       and a dedicated <b>Database Index</b> ({@code refresh_token_jti_idx}) for 
 *       O(1) lookup performance during the refresh handshake.</li>
 *   <li><b>Ownership Integrity:</b> The {@code user_id} is indexed ({@code refresh_token_user_id_idx}) 
 *       and marked as {@code updatable = false} to ensure that session ownership 
 *       cannot be hijacked or modified within the <b>Persistence Context</b>.</li>
 *   <li><b>TTL Enforcement:</b> The {@code expiresAt} field is marked as {@code nullable = false} 
 *       to ensure every token has a strictly defined lifecycle.</li>
 * </ul>
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * By persisting refresh tokens, we bridge the gap between stateless JWTs and 
 * stateful session management. This allows for immediate "Kill Switch" 
 * capability without needing to wait for the short-lived Access Token to expire.
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

    // ===================================================================================
    // SECTION 1: Identity & Metadata (Fields)
    // ===================================================================================

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
    private String jti;

    /**
     * The owner of this refresh token.
     * Fetched LAZY to optimize performance during token-only validation.
     */
    @ManyToOne(fetch = FetchType.LAZY,optional = false)
    @JoinColumn(name = "user_id",nullable = false,updatable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

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
     * Version field for JPA Optimistic Locking.
     * Prevents race conditions during concurrent token rotation.
     */
    @Version
    private Long version;

    // ===================================================================================
    // SECTION 2: Domain Logic (Factory Methods)
    // ===================================================================================

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
