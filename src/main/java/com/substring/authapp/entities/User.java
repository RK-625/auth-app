package com.substring.authapp.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.Builder.Default;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
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
 * 1. <b>Initialization:</b> Created during registration or social login (JIT Provisioning).
 * 2. <b>Persistence:</b> Managed by the <b>Persistence Context</b> and stored in the {@code users} table.
 * 3. <b>Handshake:</b> Loaded by the {@code UserDetailsService} during the authentication process.
 * 4. <b>Authorization:</b> Authorities are derived from the {@link Role} collection.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This entity is a central component within the <b>Persistence Context</b>. Hibernate manages its 
 * state transitions (Transient -> Persistent -> Detached) ensuring data consistency. 
 * It relies on the {@link com.substring.authapp.repositories.UserRepository} for transactional 
 * integrity. While it omits <b>Optimistic Locking</b> ({@code @Version}) to minimize overhead 
 * on high-frequency login timestamp updates, it enforces structural integrity through 
 * strict <b>Database Constraints</b>.
 * </p>
 *
 * <p><b>Database Constraints & Persistence Logic:</b>
 * <ul>
 *   <li><b>Unique Identity:</b> The {@code user_email} column carries a <b>Unique Constraint</b>, 
 *       preventing duplicate registrations and serving as the primary lookup handle.</li>
 *   <li><b>Immutable Metadata:</b> The {@code createdAt} field is marked as {@code updatable = false} 
 *       to preserve audit integrity within the <b>Persistence Context</b>.</li>
 *   <li><b>Length Constraints:</b> The {@code user_name} field is capped at 500 characters to 
 *       prevent buffer-related issues or storage abuse.</li>
 * </ul>
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Uses {@link FetchType#EAGER} for roles to ensure that the <b>SecurityContextHolder</b> 
 * is populated with a fully-hydrated principal, preventing {@code LazyInitializationException} 
 * during the authorization filter phase where the JPA session might already be closed.
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

    // ===================================================================================
    // SECTION 1: Identity & Profile (Fields)
    // ===================================================================================

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

    @Builder.Default
    private int tokenVersion = 0;

    // ===================================================================================
    // SECTION 2: Security & Relationships (Fields)
    // ===================================================================================

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
    @JoinTable(name = "user_roles", 
        joinColumns = @JoinColumn(name = "user_id"), 
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    @OnDelete(action = OnDeleteAction.CASCADE)
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    /**
     * Active sessions for the user.
     */
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<RefreshToken> refreshTokens = new ArrayList<>();

    /**
     * Pending password reset requests.
     */
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private ResetPasswordObject resetPasswordObject;

    // ===================================================================================
    // SECTION 3: Audit Metadata (Fields)
    // ===================================================================================

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

    // ===================================================================================
    // SECTION 4: UserDetails Contract Implementation
    // ===================================================================================

    /**
     * Maps user roles to Spring Security {@link GrantedAuthority}.
     * 
     * <p><b>Behind the Scenes:</b>
     * During the <b>Authentication Handshake</b>, Spring Security's {@code AuthenticationProvider} 
     * calls this method to populate the {@code Authentication} object with the user's roles, 
     * prefixed with {@code ROLE_} if necessary (handled by {@link Role} entity).</p>
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
     * @return true if the account is non-expired.
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked. 
     * @return true if the user is not locked.
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) have expired. 
     * @return true if the credentials are non-expired.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
