package com.substring.authapp.repositories;

import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Session Persistence Data Access Provider</h1>
 *
 * <p>Data Access Object (DAO) for managing {@link RefreshToken} persistence. This 
 * repository provides the bridge between the stateless JWT layer and the 
 * stateful session tracking store.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Discovery:</b> Locates tokens by their unique JTI handle.
 * 2. <b>Rotation:</b> Manages the transition of tokens during the refresh flow.
 * 3. <b>Revocation:</b> Facilitates immediate session termination by flagging records.
 * 4. <b>Proxying:</b> Handled by Spring Data's {@code JpaRepositoryFactory} at startup.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This repository is powered by <b>Spring Data JPA Proxy Generation</b>. At runtime, 
 * calls to {@code findByJti} are intercepted by a proxy that translates the 
 * method name into a specific indexed query. The <b>@Index optimizations</b> on 
 * the {@code jti} and {@code user_id} columns (defined in {@link RefreshToken}) 
 * are critical for O(1) performance during the high-load token refresh path.</p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * By using indexed JTI lookups, we ensure that session validation does not become 
 * a bottleneck as the {@code refresh_tokens} table grows. The <b>Spring Data Proxy</b> 
 * ensures that all operations are transactional, maintaining atomicity during 
 * sensitive token rotation operations.
 * </p>
 * 
 * @see RefreshToken For the entity structure and security purpose of JTI.
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    // ===================================================================================
    // SECTION 1: Token Discovery & Validation
    // ===================================================================================

    /**
     * Retrieves a refresh token using its unique JWT ID handle.
     *
     * <p><b>Design Rationale:</b>
     * This lookup is critical for the "Refresh Token Rotation" and "Revocation" workflows.
     * By using the JTI instead of the primary key, we decouple the internal database ID 
     * from the public-facing token handle.
     * </p>
     * 
     * @param jti The unique "JWT ID" associated with the session.
     * @return An {@link Optional} containing the token record if valid and existing.
     */
    Optional<RefreshToken> findByJti(String jti);

    // ===================================================================================
    // SECTION 2: Bulk Revocation (The "Kill Switch")
    // ===================================================================================

    /**
     * <h1>Global Session Invalidation</h1>
     * 
     * <p>Revokes all refresh tokens belonging to a specific user. This is the 
     * primary mechanism for the <b>"Token Family Revocation"</b> security pattern, 
     * used when a compromised token is detected.</p>
     * 
     * @param user The user whose sessions should be terminated.
     */
    @Modifying(clearAutomatically = true)
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = :user AND r.revoked = false")
    void revokeAllByUser(@Param("user") User user);
}
