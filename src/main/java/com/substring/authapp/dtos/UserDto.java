package com.substring.authapp.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.substring.authapp.entities.Provider;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
    
    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;
    
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotBlank(message = "{user.register.password_required}")
    @Size(min = 6, message = "{user.register.password_too_short}")
    private String password;
    
    private String name;
    private String image;
    
    @Builder.Default
    private Instant createdAt = Instant.now();
    @Builder.Default
    private Instant updatedAt = Instant.now();
    @Builder.Default
    private Provider provider = Provider.LOCAL;
    @Builder.Default
    private Set<RoleDto> roles = new HashSet<>();
    @Builder.Default
    private boolean enabled = true;
}