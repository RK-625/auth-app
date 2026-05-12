package com.substring.authapp.dtos.admin;

import com.substring.authapp.entities.Provider;
import lombok.*;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * <h1>Management/Admin User View Model</h1>
 * 
 * <p>A comprehensive Data Transfer Object (DTO) designed for administrative 
 * operations. It extends the standard user profile with internal system 
 * metadata, audit timestamps, and account status flags required by 
 * system administrators.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Mapping:</b> The {@link com.substring.authapp.services.UserService} fetches 
 *    the full {@link com.substring.authapp.entities.User} entity.
 * 2. <b>Assembly:</b> {@link org.modelmapper.ModelMapper} projects the entity 
 *    and its related {@link com.substring.authapp.entities.Role}s into this DTO.
 * 3. <b>Delivery:</b> Returned exclusively to endpoints guarded by {@code ROLE_ADMIN}.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO provides <b>Structured Decoupling</b> between the sensitive 
 * <b>Persistence Context</b> and the administrative UI. By mapping the 
 * database entity to this specific projection, we ensure that even if the 
 * {@link com.substring.authapp.entities.User} entity is expanded to include 
 * extremely sensitive internal fields (like security tokens or TOTP secrets), 
 * they are never leaked to the admin dashboard unless explicitly added to 
 * this contract. It defines a stable interface that survives database 
 * schema refactoring.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ManagementUserResponse implements Serializable {

    // ===================================================================================
    // SECTION 1: Identity & Profile (Fields)
    // ===================================================================================

    private UUID id;
    private String email;
    private String name;
    private String image;
    private Provider provider;

    // ===================================================================================
    // SECTION 2: Security & Status (Fields)
    // ===================================================================================

    @Builder.Default
    private Set<RoleDto> roles = new HashSet<>();

    private boolean enabled;

    // ===================================================================================
    // SECTION 3: Audit Metadata (Fields)
    // ===================================================================================

    private Instant createdAt;
    private Instant updatedAt;
}
