package com.substring.authapp.dtos.user;

import com.substring.authapp.dtos.admin.RoleDto;
import com.substring.authapp.entities.Provider;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * <h1>Authenticated User View Model</h1>
 * 
 * <p>A minimalist Data Transfer Object (DTO) designed specifically for the 
 * authentication payload. It contains only the essential profile information 
 * required by a frontend application to render the active user session.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Mapping:</b> Fetches the persistent {@link com.substring.authapp.entities.User} entity.
 * 2. <b>Projection:</b> Transforms the entity into this minimalist DTO using {@link org.modelmapper.ModelMapper}.
 * 3. <b>Serialization:</b> Jackson converts the object into a lean JSON response body.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * This DTO is a critical <b>Decoupling</b> layer that separates the internal 
 * {@link com.substring.authapp.entities.User} schema from the public API. Unlike 
 * the broader {@link com.substring.authapp.dtos.admin.ManagementUserResponse}, it 
 * intentionally omits audit fields ({@code createdAt}) and administrative 
 * flags ({@code enabled}). This follows the **Principle of Least Privilege**, 
 * ensuring that the API only exposes the specific subset of data required for 
 * the presentation layer while shielding the database structure.</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthUserResponse implements Serializable {

    // ===================================================================================
    // SECTION 1: Identity & Metadata (Fields)
    // ===================================================================================

    private UUID id;
    private String email;
    private String name;
    private String image;
    private Provider provider;

    // ===================================================================================
    // SECTION 2: Security Context (Fields)
    // ===================================================================================

    @Builder.Default
    private Set<RoleDto> roles = new HashSet<>();
}
