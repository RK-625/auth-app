package com.substring.authapp.dtos;

import com.substring.authapp.entities.SignUpObject;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.UUID;

/**
 * <h1>Registration Handshake Data Carrier</h1>
 * 
 * <p>A specialized Data Transfer Object (DTO) designed to carry state across the 
 * multi-phase registration lifecycle. It bridges the gap between the initial 
 * signup request and the final account provisioning.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Capture:</b> Collects user email and password in Phase 1 (Initiation).
 * 2. <b>Verification:</b> Transports the OTP and UUID token in Phase 2 (Validation).
 * 3. <b>Handover:</b> Provides the final credentials to the {@link com.substring.authapp.services.AuthService} 
 *    for {@link com.substring.authapp.entities.User} conversion in Phase 3.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This DTO is mapped to the {@link com.substring.authapp.entities.SignUpObject} entity 
 * using a {@code ModelMapper} or manual assignment. It allows the security 
 * layer to validate inputs before they ever touch the database staging table.</p>
 * 
 * <p><b>Design Rationale (Multi-Phase Carry):</b>
 * By using a single DTO for multiple phases, we maintain a consistent API schema. 
 * The {@link Serializable} implementation ensures compatibility with distributed 
 * caching or session clustering if the handshake state needs to be offloaded from 
 * the local JVM.</p>
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class SignUpObjectDto implements Serializable {
    private String email;
    private String otp;
    @NotNull
    private UUID signUpToken;
    private String password;
}