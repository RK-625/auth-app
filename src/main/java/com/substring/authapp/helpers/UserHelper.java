package com.substring.authapp.helpers;

import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.util.Pair;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

/**
 * <h1>User Lifecycle Assistant</h1>
 *
 * <p>This helper component provides utility methods for user-related operations, including validation,
 * entity assembly, and security token generation. It serves to keep the service layer focused
 * on business orchestration by encapsulating low-level assembly logic.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Validation:</b> Enforces business constraints on user registration data.
 * 2. <b>Assembly:</b> Converts credentials to Entities, applying password encoding and role linking.
 * 3. <b>Persistence Delegation:</b> Interfaces with {@link UserRepository} for data access.
 * 4. <b>Security Generation:</b> Produces cryptographically secure OTPs for sensitive flows.</p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * Utilizes {@link PasswordEncoder} for credential hashing. It interacts with the {@link RoleRepository} 
 * to ensure that every new user is linked to a valid persistent {@link Role} entity within the JPA lifecycle.</p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
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

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final MessageHelper messageHelper;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    @org.springframework.beans.factory.annotation.Value("${app.validation.min-password-length:6}")
    private int minPasswordLength;

    @org.springframework.beans.factory.annotation.Value("${app.validation.max-password-length:72}")
    private int maxPasswordLength;

    // ===================================================================================
    // SECTION 2: Validation Logic (Public)
    // ===================================================================================

    /**
     * <h1>Identity Validation Bridge (Authentication)</h1>
     * 
     * <p>Finds a user by email specifically for authentication handshakes. 
     * This method maps missing users to a {@link org.springframework.security.authentication.BadCredentialsException} 
     * to prevent "User Enumeration" attacks.</p>
     * 
     * @param email The user email.
     * @return The found {@link User}.
     * @throws org.springframework.security.authentication.BadCredentialsException if the user is not found.
     */
    public User validateAndGetUserForAuth(String email) {
        return findUserByEmailOrThrow(email, 
            new org.springframework.security.authentication.BadCredentialsException(
                messageHelper.getMessage("auth.forget.email_not_found")
            )
        );
    }

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
     * <p><b>Design Rationale (The "Why"):</b>
     * Performing these checks in the Helper layer provides <b>Fail-Fast</b> behavior. 
     * It prevents the application from initiating expensive transaction resources (database locks, 
     * password hashing) if the request is fundamentally invalid.
     * </p>
     * 
     * @param email The candidate email address.
     * @param password The candidate password.
     * @throws IllegalArgumentException If email is missing, password is too short, or email already exists.
     */
    public void validateUserForSignup(String email, String password) {
        if (email == null || email.isBlank() || userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.not_available"));
        }
        
        if (password == null || password.length() < minPasswordLength || password.length() > maxPasswordLength) {
             throw new IllegalArgumentException(messageHelper.getMessage("user.register.password_too_short"));
        }
    }

    /**
     * <h1>Email Validation Gatekeeper</h1>
     *
     * <p>Enforces basic uniqueness and presence constraints specifically for the email field.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates presence of the email string.
     * 2. Defers to {@link UserRepository#existsByEmail(String)} for collision detection.</p>
     *
     * <p><b>Design Rationale:</b>
     * Isolated validation for flows that only collect an email (Phase 1 of Signup) before a password is required.</p>
     *
     * @param email The candidate email address.
     * @throws IllegalArgumentException If the email is blank or already exists.
     */
    public void validateSignUpEmail(String email) {
        if (email == null || email.isBlank() || userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.not_available"));
        }
    }


    // ===================================================================================
    // SECTION 3: Entity Assembly and Lookup (Public)
    // ===================================================================================

    /**
     * <h1>Persistent Entity Orchestrator</h1>
     * 
     * <p>Transforms raw credentials and profile data into a fully-provisioned, 
     * persistent {@link User} entity. This method handles the critical transition 
     * from "untrusted" API data to "trusted" database state.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Assembly:</b> Builds the {@link User} entity using the provided credentials.
     * 2. <b>Security Injection:</b> Hashes the plaintext password and sets the authentication {@link Provider}.
     * 3. <b>Authorization Linking:</b> Discovers and attaches the mandatory {@link Role} from the database.
     * 4. <b>Persistence:</b> Commits the new user to the {@link UserRepository}.
     * </p>
     * 
     * <p><b>Behind the Scenes (Component Interaction):</b>
     * - Uses {@link PasswordEncoder} to ensure credentials never hit the database in plaintext.
     * - Interfaces with {@link RoleRepository} to transition the {@link Role} into the <b>Managed</b> state 
     *   before linking it to the user.
     * </p>
     * 
     * <p><b>Design Rationale (The Bridge):</b>
     * This helper acts as a <b>Security Filter</b>. By manually assembling the entity, 
     * we prevent "Mass Assignment" attacks. Returning the raw {@link User} entity allows 
     * the calling service to decide which specific DTO to map the result into, preserving 
     * clean architectural boundaries.
     * </p>
     * 
     * @param email User email identifier.
     * @param password Raw plaintext password.
     * @param name Optional display name.
     * @param provider The identity issuer (LOCAL, GITHUB, etc.).
     * @param roleName The base authority to grant (e.g., ROLE_USER).
     * @return The fully provisioned and persisted {@link User} entity.
     * @throws ResourceNotFoundException If the requested role does not exist in the DB.
     */
    public User buildAndSaveUser(String email, String password, String name, Provider provider, UserRole roleName) {
        // 1. Build Entity structure
        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .name(name)
                .provider(provider)
                .enabled(true)
                .build();

        // 2. Link mandatory Authorization Roles
        Role defaultRole = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("role.not_found")));
        
        Set<Role> roles = new HashSet<>();
        roles.add(defaultRole);
        user.setRoles(roles);
        
        // 3. Persist and return entity
        return userRepository.save(user);
    }

    /**
     * <h1>Standardized Lookup Utility</h1>
     * 
     * <p>Finds a user by email or throws a customized exception if not found.</p>
     *
     * <p><b>Design Rationale:</b>
     * Simplifies the common "find or throw" pattern used throughout the service layer,
     * providing a consistent entry point for user lookups while allowing callers to 
     * inject specific semantic exceptions (e.g., {@code BadCredentialsException} vs {@code ResourceNotFoundException}).</p>
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


    // ===================================================================================
    // SECTION 4: Credential Generation (Functional Interface Pattern)
    // ===================================================================================

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
     * Uses a <b>Functional Interface ({@link Predicate})</b> approach. This allows the 
     * method to be reused across completely different repositories (Signup Table vs. 
     * Password Reset Table) without tight coupling to specific entity types.</p>
     * 
     * @param collisionChecker A function that returns true if the generated keys already exist in the target DB.
     * @return A guaranteed-unique {@link Pair} of OTP and UUID Token.
     */
    public Pair<String, UUID> generateUniqueHandshakeKeys(Predicate<Pair<String, UUID>> collisionChecker) {
        Pair<String, UUID> keys = generateSecureOtpAndToken();
        while (collisionChecker.test(keys)) {
            keys = generateSecureOtpAndToken();
        }
        return keys;
    }

    /**
     * Generates a cryptographically secure 6-digit OTP and a unique reset token.
     *
     * <p><b>Behind the Scenes (Cryptographic Strength):</b>
     * Uses {@link java.security.SecureRandom} instead of {@code java.util.Random} to ensure
     * that the generated sequence is non-deterministic and resistant to prediction attacks.</p>
     *
     * <p><b>Design Rationale:</b>
     * OTPs are sensitive security credentials. Using a PRNG (Pseudo-Random Number Generator)
     * suitable for cryptography is mandatory to prevent attackers from brute-forcing reset codes.</p>
     *
     * @return A {@link Pair} containing the OTP string and a {@link UUID} token.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static Pair<String, UUID> generateSecureOtpAndToken() {
         int otp = 100000 + SECURE_RANDOM.nextInt(900000);
         UUID resetToken = UUID.randomUUID();
         return Pair.of(String.valueOf(otp), resetToken);
    }
}