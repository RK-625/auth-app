package com.substring.authapp.entities;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;


@AllArgsConstructor
@NoArgsConstructor
@RequiredArgsConstructor
@Getter
@Setter
@Entity
public class ResetPasswordObject {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    private String Otp;
    private Instant createdAt;
    private Instant expiresAt ;
    private boolean used;

    @NotNull
    @Column(nullable = false, unique = true)
    private UUID resetToken;

    public ResetPasswordObject(User user, String otp, UUID resetToken) {
        this.user = user;
        Otp = otp;
        this.resetToken = resetToken;
    }

    @PrePersist
    public void prePersist() {
        createdAt = Instant.now();
        expiresAt = Instant.now().plusSeconds(60);
        used = false;
    }
}
