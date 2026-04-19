package com.substring.authapp.helpers;

import com.substring.authapp.dtos.SignUpObjectDto;
import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import com.substring.authapp.helpers.MessageHelper;
import org.modelmapper.ModelMapper;
import org.springframework.data.util.Pair;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * <h1>User Lifecycle Assistant</h1>
 *
 * <p>This helper component provides utility methods for user-related operations, including validation,
 * entity assembly, and security token generation. It serves to keep the service layer focused
 * on business orchestration by encapsulating low-level assembly logic.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Validation:</b> Enforces business constraints on user registration data.
 * 2. <b>Assembly:</b> Converts DTOs to Entities, applying password encoding and role linking.
 * 3. <b>Persistence Delegation:</b> Interfaces with {@link UserRepository} for data access.
 * 4. <b>Security Generation:</b> Produces cryptographically secure OTPs for sensitive flows.</p>
 *
 * <p><b>Behind the Scenes:</b>
 * Utilizes {@link ModelMapper} for field synchronization and {@link PasswordEncoder} for credential hashing.
 * It interacts with the {@link RoleRepository} to ensure that every new user is linked to a valid
 * persistent {@link Role} entity within the JPA lifecycle.</p>
 *
 * <p><b>Design Rationale:</b>
 * By centralizing "find-or-throw" logic and complex entity building here, we promote the DRY (Don't Repeat Yourself)
 * principle and ensure that security standards (like password encoding) are applied consistently.</p>
 *
 * @author Gemini CLI
 * @see UserRepository
 * @see RoleRepository
 * @see PasswordEncoder
 */
@Component
@RequiredArgsConstructor
public class UserHelper {

    private final MessageHelper messageHelper;
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    /**
     * <h1>Registration Gatekeeper</h1>
     * 
     * <p>Enforces strict business rules on incoming registration data to ensure 
     * data integrity and account uniqueness before any persistence occurs.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Null Check:</b> Verifies that critical identity fields (Email) are present.
     * 2. <b>Policy Enforcement:</b> Ensures the password meets complexity/length requirements.
     * 3. <b>Uniqueness Verification:</b> Queries the database to prevent duplicate account creation.
     * </p>
     * 
     * <p><b>Behind the Scenes (Database Handshake):</b>
     * This method triggers an optimized {@code EXISTS} query via {@link UserRepository#existsByEmail(String)}. 
     * This is a high-performance check that returns as soon as a single matching record is found, 
     * preventing unnecessary full-table scans.
     * </p>
     * 
     * <p><b>Design Rationale:</b>
     * Performing these checks in the Helper layer provides <b>Fail-Fast</b> behavior. 
     * It prevents the application from initiating expensive transaction resources (database locks, 
     * password hashing) if the request is fundamentally invalid.
     * </p>
     * 
     * @param userDto Incoming user data to validate.
     * @throws IllegalArgumentException If email is missing, password is too short, or email already exists.
     */
    public void validateUserForSignup(String email,String password){
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_required"));
        }
        
        if (password == null || password.length() < 6) {
             throw new IllegalArgumentException(messageHelper.getMessage("user.register.password_too_short"));
        }

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_exists"));
        }
    }

    /**
     * <h1>Persistent Entity Orchestrator</h1>
     * 
     * <p>Transforms a raw data transfer object into a fully-provisioned, persistent {@link User} entity. 
     * This method handles the critical transition from "untrusted" API data to "trusted" database state.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Assembly:</b> Converts {@link UserDto} to {@link User} entity, ensuring sensitive fields like {@code id} are ignored.
     * 2. <b>Security Injection:</b> Hashes the plaintext password and sets the authentication {@link Provider}.
     * 3. <b>Authorization Linking:</b> Discovers and attaches the mandatory {@link Role} from the database.
     * 4. <b>Persistence:</b> Commits the new user to the {@link UserRepository}.
     * 5. <b>Projection:</b> Maps the result back to a sanitized DTO for the client.
     * </p>
     * 
     * <p><b>Behind the Scenes (Component Interaction):</b>
     * - Uses {@link PasswordEncoder} to ensure credentials never hit the database in plaintext.
     * - Interfaces with {@link RoleRepository} to transition the {@link Role} into the <b>Managed</b> state 
     *   before linking it to the user.
     * - The final {@link UserRepository#save(Object)} call triggers the JPA lifecycle events and 
     *   database constraints.
     * </p>
     * 
     * <p><b>Design Rationale (The Bridge):</b>
     * This helper acts as a <b>Security Filter</b>. By manually controlling the assembly (even with 
     * {@link ModelMapper}), we prevent "Mass Assignment" attacks. Sanitization of sensitive 
     * fields like {@code id} and {@code password} is delegated to the JSON layer via 
     * {@code WRITE_ONLY} access constraints, ensuring a clean and efficient assembly flow.
     * </p>
     * 
     * @param userDto Incoming user data from the API.
     * @param provider The identity issuer (LOCAL, GITHUB, etc.).
     * @param roleName The base authority to grant (e.g., ROLE_USER).
     * @return A sanitized DTO representing the persisted user.
     * @throws ResourceNotFoundException If the requested role does not exist in the DB.
     */
    public UserDto buildAndSaveUser(UserDto userDto, Provider provider, UserRole roleName) {
        // 1. Convert DTO to Entity structure
        User user = modelMapper.map(userDto, User.class);
        
        // 2. Apply Security and Provider constraints
        user.setProvider(provider);
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        // 3. Link mandatory Authorization Roles
        Role defaultRole = roleRepository.findByName(roleName.name())
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("role.not_found")));
        
        Set<Role> roles = new HashSet<>();
        roles.add(defaultRole);
        user.setRoles(roles);
        
        // 4. Persist and return sanitized view
        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser, UserDto.class);
    }

    /**
     * Standardized lookup utility to find a user or fail with a specific exception.
     *
     * <p><b>Design Rationale:</b>
     * Simplifies the common "find or throw" pattern used throughout the service layer,
     * providing a consistent entry point for user lookups.</p>
     *
     * @param email The email to search for.
     * @param notFoundException The exception to throw if the user is missing.
     * @return The found {@link User} entity.
     * @throws IllegalArgumentException If the email is blank.
     */
    public User findUserByEmailOrThrow(String email, RuntimeException notFoundException) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_required"));
        }
        return userRepository.findByEmail(email).orElseThrow(() -> notFoundException);
    }

    /**
     * Generates a cryptographically secure 6-digit OTP and a unique reset token.
     *
     * <p><b>Behind the Scenes:</b>
     * Uses {@link java.security.SecureRandom} instead of {@code java.util.Random} to ensure
     * that the generated sequence is non-deterministic and resistant to prediction attacks.</p>
     *
     * <p><b>Design Rationale:</b>
     * OTPs are sensitive security credentials. Using a PRNG (Pseudo-Random Number Generator)
     * suitable for cryptography is mandatory to prevent attackers from guessing reset codes.</p>
     *
     * @return A {@link Pair} containing the OTP string and a {@link UUID} token.
     */
    public static Pair<String,UUID> generateSecureOtpAndToken() {
         SecureRandom secureRandom = new SecureRandom();
         int otp = 100000 + secureRandom.nextInt(900000);
         UUID resetToken = UUID.randomUUID();
         return Pair.of(String.valueOf(otp), resetToken);
    }

    /**
     * <h1>Generic Handshake Credential Factory</h1>
     * 
     * <p>Centralizes the generation of unique security credentials (OTP + Token) 
     * while enforcing collision resistance against a provided persistence check.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. Generates a cryptographically secure pair via {@link #generateSecureOtpAndToken()}.
     * 2. Executes the provided {@code collisionChecker} function to verify uniqueness.
     * 3. Retries generation until a non-colliding pair is established.
     * </p>
     * 
     * <p><b>Behind the Scenes:</b>
     * Uses a <b>Functional Interface</b> approach, allowing this method to be 
     * reused across different repositories (Signup vs. Forget Password) without 
     * tight coupling to specific entity types.</p>
     * 
     * @param collisionChecker A function that returns true if the generated keys already exist.
     * @return A unique {@link Pair} of OTP and UUID Token.
     */
    public Pair<String, UUID> generateUniqueHandshakeKeys(java.util.function.Predicate<Pair<String, UUID>> collisionChecker) {
        Pair<String, UUID> keys = generateSecureOtpAndToken();
        while (collisionChecker.test(keys)) {
            keys = generateSecureOtpAndToken();
        }
        return keys;
    }

    public void validateSignUpEmail(String email){
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_required"));
        }
        if(userRepository.existsByEmail(email)){
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_exists"));
        }
    }

}
