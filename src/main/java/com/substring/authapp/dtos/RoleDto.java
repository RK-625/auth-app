package com.substring.authapp.dtos;

import com.substring.authapp.entities.Role;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.io.Serializable;
import java.util.UUID;

/**
 * <h1>Role Data Transfer Object</h1>
 *
 * <p>Data Transfer Object representing a user's role/authority within the system.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Sent from the client when assigning roles, or returned within the {@link UserDto} payload.
 * 2. <b>Validation:</b> JSR-303 constraints ensure that when creating or modifying roles, the name is not blank.
 * 3. <b>Mapping:</b> Converted to/from the {@link com.substring.authapp.entities.Role} entity during access control operations.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This DTO is used by {@link com.substring.authapp.services.UserService} to safely transfer role information without exposing the persistence entity. 
 * Spring Security utilizes the underlying entity to populate the {@link org.springframework.security.core.GrantedAuthority} collections.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Decoupling the role representation from the entity prevents accidental mass-assignment of sensitive role flags (e.g., internal permissions) 
 * and ensures the API contract is focused purely on the role identifier and name.
 * </p>
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class RoleDto implements Serializable {
    private UUID id;

    @NotBlank(message = "Role name is required")
    private String name;
}