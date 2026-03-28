package com.substring.authapp.entities;


import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

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
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(unique = true,name = "jti",nullable = false,updatable = false)
    private String jti; // this is the refersh toke uuid
    @ManyToOne(fetch = FetchType.LAZY,optional = false)
    @JoinColumn(name = "user_id",nullable = false,updatable = false)
    private User user; // the user id the refersh token belongs to
    @Column(updatable = false,nullable = false)
    private Instant createdAt;
    @Column(updatable = false,nullable = false)
    private Instant expiresAt;
    @Column(nullable = false)
    private boolean revoked;
    private String replacedByToken;

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
