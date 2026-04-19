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
 * <h1>Data Transfer Object for user profile management and registration.</h1>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Incoming JSON is deserialized into this DTO by Jackson.
 * 2. <b>Validation:</b> The {@code DispatcherServlet} triggers Jakarta Bean Validation ({@code @Valid}) before the controller method is executed.
 * 3. <b>Mapping:</b> Validated data is transformed into the {@link com.substring.authapp.entities.User} entity using the {@code UserHelper} bridge.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This DTO is the primary mechanism for <b>Mass Assignment Protection</b>. By only exposing 
 * necessary fields, we prevent "Over-Posting" attacks where a malicious client might attempt 
 * to set restricted fields (e.g., account status or roles) during registration. The 
 * <b>@Valid annotation</b> ensures that invalid data triggers a {@code MethodArgumentNotValidException} 
 * early in the request lifecycle, before it reaches any service logic.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Decoupling the API model from the persistence entity ensures that internal database changes 
 * do not break external API contracts. We also utilize {@link JsonProperty.Access#WRITE_ONLY} 
 * on the password field to prevent it from ever being serialized back to the client, 
 * maintaining a one-way flow for sensitive data.
 * </p>
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class UserDto implements  Serializable {
    /**
     * Unique identifier for the user.
     * 
     * <p><b>Security Context: READ_ONLY</b></p>
     * <p><b>Behind the Scenes:</b>
     * Configured as {@code READ_ONLY} to allow the client to receive and store 
     * the UUID for future requests (like Path Variables), while preventing 
     * the client from attempting to overwrite or inject an ID during a 
     * {@code POST} or {@code PUT} request body.
     * </p>
     * 
     * <p><b>Design Rationale:</b>
     * This acts as an <b>Immutability Shield</b>. The server is the sole 
     * source of truth for the ID. By making it READ_ONLY, we ensure the 
     * contract between the client and server is clear: "You can see who 
     * you are, but you cannot change your core identity."
     * </p>
     */
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private UUID id;

    /**
     * Primary email used for account identification and notifications.
     */
    @NotBlank(message = "{user.register.email_required}")
    @Email(message = "{user.register.email_invalid}")
    private String email;

    /**
     * Raw password provided during registration or login.
     * Hidden from outbound JSON to prevent security leaks.
     */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotBlank(message = "{user.register.password_required}")
    @Size(min = 6, message = "{user.register.password_too_short}")
    private String password;

    /**
     * Human-readable display name.
     */
    private String name;

    /**
     * Profile image identifier or URL.
     */
    private String image;

    /**
     * Audit field for account age tracking.
     */
    @Builder.Default
    private Instant createdAt = Instant.now();

    /**
     * Audit field for profile freshness tracking.
     */
    @Builder.Default
    private Instant updatedAt = Instant.now();

    /**
     * Identifies if the user is LOCAL or from an OAuth2 provider.
     */
    @Builder.Default
    private Provider provider = Provider.LOCAL;

    /**
     * Flattened set of role descriptors for the user.
     */
    @Builder.Default
    private Set<RoleDto> roles = new HashSet<>();

    /**
     * Administrative flag for account status.
     */
    @Builder.Default
    private boolean enabled = true;
}