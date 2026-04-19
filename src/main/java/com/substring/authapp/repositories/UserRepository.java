package com.substring.authapp.repositories;

import com.substring.authapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Central Data Access Object (DAO) for managing {@link User} entities.</h1>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Method Parsing:</b> Spring Data JPA parses method names (e.g., {@code findByEmail}) at startup to generate the underlying JPQL.
 * 2. <b>Proxy Execution:</b> At runtime, a JDK Dynamic Proxy intercepts calls and executes the generated SQL via the {@code EntityManager}.
 * 3. <b>Result Mapping:</b> The returned JDBC {@code ResultSet} is mapped back into managed JPA entities within the current persistence context.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This repository leverages <b>Spring Data JPA Proxying</b>. Instead of a concrete implementation, Spring provides a proxy that 
 * delegates to {@code SimpleJpaRepository}. For the {@code findByEmail} method, the system relies on an <b>Index-Driven Lookup</b> 
 * on the database's {@code email} column, ensuring $O(1)$ or $O(\log n)$ search complexity, which is critical for high-frequency 
 * authentication handshakes.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * The repository pattern is chosen to abstract the underlying persistence technology. By using {@link UUID} as the primary key, 
 * we prevent ID enumeration attacks and ensure global uniqueness across distributed systems, while the index-driven lookups 
 * mitigate performance bottlenecks during the {@code CustomUserDetailService} lookup phase.
 * </p>
 */
public interface UserRepository extends JpaRepository<User, UUID> {
    
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
