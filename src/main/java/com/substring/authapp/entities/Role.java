package com.substring.authapp.entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "roles")
public class Role {
    @Id
    private UUID id = UUID.randomUUID();
    @Enumerated(value = EnumType.STRING)
    @Column(name = "role_name",unique = true,nullable = false)
    private String name;
}
