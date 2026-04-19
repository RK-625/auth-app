package com.substring.authapp.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.Builder.Default;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.*;

/**
 * <h1>Core Identity Domain Entity</h1>
 *
 * <p>Represents a registered participant in the authentication system. This entity 
 * serves as the primary principal for all security operations and implements the 
 * mandatory {@link UserDetails} contract for Spring Security.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. Initialized during registration or social login (JIT Provisioning).
 * 2. Persisted in the {@code users} table with a cryptographically hashed password.
 * 3. Loaded by the {@code UserDetailsService} during the authentication handshake.
 * 4. Referenced by {@link RefreshToken} and {@link Role} entities to build the security context.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * Managed by Hibernate, this entity uses a UUID strategy for decentralized ID generation.
 * It integrates with the <b>Persistence Context</b> to provide automatic auditing via 
 * {@link CreationTimestamp} and {@link UpdateTimestamp}. The relationship with 
 * {@link Role} is fetched eagerly to ensure that authorities are available 
 * immediately during the authorization filter phase.
 * </p>
 *
 * <p><b>Security Integrity:</b>
 * <ul>
 *   <li><b>{@code @Column(updatable = false)}:</b> Applied to {@code createdAt} to preserve 
 *       the immutable audit trail of account creation, preventing administrative or 
 *       malicious tampering.</li>
 *   <li><b>{@link #getAuthorities()}:</b> Flattens the many-to-many role relationship 
 *       into {@link SimpleGrantedAuthority} objects for Spring's access decision managers.</li>
 * </ul>
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Uses {@link FetchType#EAGER} for the {@code roles} relationship. While LAZY is generally 
 * preferred, EAGER fetching here ensures that authorities are fully loaded and 
 * available to the {@link org.springframework.security.access.intercept.FilterSecurityInterceptor} 
 * without requiring a new transaction during authorization checks.
 * </p>
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "users")
public class User implements UserDetails {
    /**
     * Unique identifier for the user.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    private UUID id;

    /**
     * Unique email address used for authentication and communication.
     */
    @Column(name = "user_email", unique = true)
    private String email;

    /**
     * Display name of the user.
     */
    @Column(name = "user_name", length = 500)
    private String name;

    /**
     * Encoded password for the user. 
     * Security Note: Should never be stored as plain text.
     */
    private String password;

    /**
     * URL or identifier for the user's profile image.
     */
    private String image;

    /**
     * Indicates if the user account is enabled for login.
     */
    @Builder.Default
    private boolean enabled = true;
    
    /**
     * Timestamp indicating when the user account was created.
     */
    @CreationTimestamp
    @Column(updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
    
    /**
     * Timestamp indicating the last update to the user account details.
     */
    @UpdateTimestamp
    @Builder.Default
    private Instant updatedAt = Instant.now();
    
    /**
     * The authentication provider used for this user account (e.g., LOCAL, GOOGLE, GITHUB).
     */
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Provider provider = Provider.LOCAL;

    /**
     * Roles associated with this user, used for role-based access control (RBAC).
     * Fetched eagerly to ensure roles are available during authentication checks.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user->roles", 
        joinColumns = @JoinColumn(name = "user_id"), 
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    /**
     * Maps user roles to Spring Security {@link GrantedAuthority}.
     * 
     * @return a collection of authorities based on the user's roles.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .toList();
    }

    /**
     * Returns the username used to authenticate the user. 
     * In this implementation, the email serves as the username.
     * 
     * @return the user's email address.
     */
    @Override
    public String getUsername() {
        return this.email;
    }

    /**
     * Indicates whether the user's account has expired. 
     * An expired account cannot be authenticated.
     * 
     * @return true if the account is non-expired, false otherwise.
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked. 
     * A locked user cannot be authenticated.
     * 
     * @return true if the user is not locked, false otherwise.
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) have expired. 
     * Expired credentials prevent authentication.
     * 
     * @return true if the credentials are non-expired, false otherwise.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
