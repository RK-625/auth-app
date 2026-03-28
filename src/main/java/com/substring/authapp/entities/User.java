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
 * Entity representing a User in the system.
 * Implements {@link UserDetails} for Spring Security integration,
 * providing authentication and authorization capabilities.
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
