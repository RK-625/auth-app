package com.substring.authapp.repositories;

import com.substring.authapp.entities.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Core Identity Data Access Provider</h1>
 *
 * <p>Central repository for managing {@link User} entities. This interface serves 
 * as the primary gateway for identity retrieval and persistence during the 
 * authentication and authorization lifecycles.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Method Parsing:</b> Spring Data JPA parses method signatures at startup to generate JPQL.
 * 2. <b>Proxy Generation:</b> At runtime, a JDK Dynamic Proxy ({@code SimpleJpaRepository}) handles execution.
 * 3. <b>Transaction Boundary:</b> Operations are wrapped in transactions via the {@code TransactionInterceptor}.
 * 4. <b>Result Mapping:</b> Hibernate maps the {@code ResultSet} to the {@link User} domain model.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This repository utilizes <b>Spring Data JPA Proxy Generation</b> to eliminate 
 * boilerplate DAO code. It leverages <b>Index-Driven Lookups</b> on the {@code user_email} 
 * column (defined at the entity level) to ensure O(1) retrieval performance during 
 * high-frequency login attempts. The {@link com.substring.authapp.security.CustomUserDetailService} 
 * relies on this proxy to hydrate the security principal efficiently.</p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Abstracting data access through an interface allows the business layer to remain 
 * agnostic of the underlying persistence implementation. The use of unique indices 
 * on the email column not only enforces business rules but also optimizes the 
 * <b>Persistence Context</b> lookup speed, critical for maintaining low latency 
 * in the authentication handshake.
 * </p>
 */
public interface UserRepository extends JpaRepository<User, UUID> {

    // ===================================================================================
    // SECTION 1: Identity Discovery
    // ===================================================================================

    /**
     * Finds a user by their unique email address.
     * 
     * <p><b>Implementation Workflow:</b>
     * The {@code AuthenticationManager} triggers this lookup during the <b>DaoAuthenticationProvider</b> handshake. 
     * If found, the user is returned as an {@link Optional} to be converted into a {@code UserDetails} object.
     * </p>
     *
     * @param email The user's primary email handle.
     * @return An {@link Optional} allowing for safe handling of missing users.
     */
    Optional<User> findByEmail(String email);

    /**
     * Predicate check for existing email addresses.
     *
     * <p><b>Behind the Scenes:</b>
     * This method generates an {@code EXISTS} SQL clause rather than a {@code SELECT *}. This is a critical 
     * performance optimization that avoids loading the entire entity into the 1st-level cache.
     * </p>
     * 
     * @param email The email to verify.
     * @return true if the email is already registered in the system.
     */
    boolean existsByEmail(String email);

    // ===================================================================================
    // SECTION 2: Lifecycle Operations
    // ===================================================================================

    /**
     * Hard delete of a user record.
     *
     * <p><b>Design Rationale:</b>
     * While soft deletes are common, a hard delete is provided for GDRP compliance and data purging. 
     * This operation is automatically wrapped in a transaction by the Spring Data proxy.
     * </p>
     * 
     * @param id The UUID of the user to purge.
     */
    void deleteUserById(UUID id);
}
by the Spring Data proxy.
     * </p>
     * 
     * @param id The UUID of the user to purge.
     */
    void deleteUserById(UUID id);
}
