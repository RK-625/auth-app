package com.substring.authapp.dtos.admin;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.io.Serializable;
import java.util.UUID;

/**
 * <h1>Role Representation DTO</h1>
 * 
 * <p>A lightweight, serializable data carrier for system authorization roles. 
 * This DTO is used to project the persistent {@link com.substring.authapp.entities.Role} 
 * entity into a format suitable for API consumption, ensuring that internal 
 * JPA state (like Hibernate proxies) doesn't leak into the presentation layer.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Extraction:</b> The role details are extracted from the persistent entity.
 * 2. <b>Projection:</b> Mapped to this DTO to remove circular dependencies or lazy-loading issues.
 * 3. <b>Serialization:</b> Delivered as part of user profile or administrative responses.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * By using a separate DTO for roles, we <b>Decouple</b> the security authority 
 * representation from the underlying database model. This ensures that the 
 * API contract remains stable even if the database schema for roles changes 
 * (e.g., migrating from an ID-based system to a string-based authority). 
 * It prevents the <b>Persistence Context</b> details from bleeding into 
 * the JSON responses, maintaining a clean architectural boundary.</p>
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class RoleDto implements Serializable {

    // ===================================================================================
    // SECTION 1: Authority Data (Fields)
    // ===================================================================================

    private UUID id;

    @NotBlank(message = "Role name is required")
    private String name;
}
