package com.substring.authapp.dtos.user;

import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * <h1>User Inbound Update Command</h1>
 * 
 * <p>A restricted, immutable payload designed for self-service profile updates. 
 * This DTO allows users to modify their non-sensitive profile attributes 
 * while maintaining strict control over core identity fields.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Validation:</b> Spring Validator checks field length constraints.
 * 2. <b>Merging:</b> The {@link com.substring.authapp.services.UserService} merges these 
 *    fields into the active {@link com.substring.authapp.entities.User} entity.
 * 3. <b>Persistence:</b> The updated entity is flushed to the database.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO is the primary defense against <b>Mass Assignment Attacks</b> during 
 * profile updates. It provides essential <b>Decoupling</b> by creating a 
 * separate update-only view of the user. By <b>not</b> including fields like 
 * {@code id}, {@code email}, {@code provider}, or {@code roles}, we ensure 
 * that a user cannot elevate their privileges or change their primary 
 * identifier through this endpoint. It maintains a stable API contract 
 * regardless of internal changes to the {@link com.substring.authapp.entities.User} 
 * schema.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserUpdateRequest implements Serializable {

    // ===================================================================================
    // SECTION 1: Updatable Profile Attributes (Fields)
    // ===================================================================================

    @Size(max = 100, message = "{user.update.name_too_long}")
    private String name;

    @Size(max = 2048, message = "{user.update.image_too_long}")
    private String image;
}
