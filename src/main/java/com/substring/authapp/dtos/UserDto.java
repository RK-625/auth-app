package com.substring.authapp.dtos;

import com.substring.authapp.entities.Provider;
import lombok.*;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * DTO for {@link com.substring.authapp.entities.User}
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class UserDto implements  Serializable {
    private UUID id;
    private String email;
    private String name;
    private String password;
    private String image;
    private boolean enabled = true;
    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();
    private Provider provider = Provider.LOCAL;
    private Set<RoleDto> roles = new HashSet<>();
}