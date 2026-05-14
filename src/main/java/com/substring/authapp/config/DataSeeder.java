package com.substring.authapp.config;

import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.utils.PrivacyHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

/**
 * <h1>Autonomous Database Provisioning Engine</h1>
 * 
 * <p>This component serves as the application's "Day Zero" initializer. It implements the 
 * {@link CommandLineRunner} interface to execute critical data setup logic immediately 
 * after the Spring Application Context has fully ignited, but before the web container 
 * starts accepting ingress traffic.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Discovery:</b> Intercepts the startup lifecycle via {@code run()}.
 * 2. <b>Authority Synchronization:</b> Ensures all {@link UserRole} constants exist as persistent {@link Role} entities.
 * 3. <b>Root Identity Injection:</b> Provisions the master administrative account if the identity store is empty.
 * 4. <b>Cryptographic Handshake:</b> Leverages the system's real {@link PasswordEncoder} to ensure hash consistency.
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This configuration works in tandem with the <b>Persistence Context</b>. By using {@link Transactional}, 
 * it ensures that role creation and user assignment occur within a single atomic unit of work. 
 * It interacts with {@link UserRepository} and {@link RoleRepository} to perform 
 * <b>Idempotent Lookups</b>, preventing duplicate key violations on subsequent restarts.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * Unlike static SQL scripts (e.g., {@code data.sql}), this programmatic approach ensures 
 * <b>Algorithm Portability</b>. If the {@link PasswordEncoder} is upgraded (e.g., from BCrypt 
 * to Argon2), this seeder automatically applies the new hashing logic without requiring 
 * manual SQL updates.
 * </p>
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @org.springframework.beans.factory.annotation.Value("${app.security.root.email}")
    private String rootEmail;

    @org.springframework.beans.factory.annotation.Value("${app.security.root.password}")
    private String rootPassword;

    /**
     * Entry point for the startup provisioning logic.
     * 
     * @param args Incoming command line arguments (unused).
     */
    @Override
    @Transactional
    public void run(String... args) {
        log.info("🏁 Initiating System Provisioning Handshake...");

        // 1. Synchronize Authorization Roles
        syncRoles();

        // 2. Inject Primary Root Identity
        injectRootUser();

        // 3. Inject Standard Test User
        injectTestUser();

        log.info("✅ System Provisioning Completed.");
    }

    /**
     * Ensures that the database authority table is synchronized with the 
     * {@link UserRole} enumeration.
     */
    private void syncRoles() {
        for (UserRole roleType : UserRole.values()) {
            // Updated: Pass the Enum directly instead of .name()
            if (roleRepository.findByName(roleType).isEmpty()) {
                log.info("   -> Provisioning missing authority: {}", roleType);
                Role role = Role.builder()
                        .name(roleType)
                        .build();
                roleRepository.save(role);
            }
        }
    }

    /**
     * Provisions the master 'Root' account. This account acts as the ultimate 
     * system authority for initial setup and recovery.
     */
    private void injectRootUser() {
        if (!userRepository.existsByEmail(rootEmail)) {
            log.info("   -> Injecting Master Root Identity: {}", PrivacyHelper.maskEmail(rootEmail));

            // Updated: Pass the Enum directly instead of .name()
            Role rootRole = roleRepository.findByName(UserRole.ROLE_ROOT)
                    .orElseThrow(() -> new IllegalStateException("Critical Failure: ROLE_ROOT not found after sync"));

            User rootUser = User.builder()
                    .email(rootEmail)
                    .name("System Root")
                    .password(passwordEncoder.encode(rootPassword)) 
                    .enabled(true)
                    .provider(Provider.ORGANIZATION)
                    .roles(Set.of(rootRole))
                    .build();

            userRepository.save(rootUser);
            log.info("   -> Root Identity successfully persistent.");
        } else {
            log.debug("   -> Root Identity already exists. Skipping injection.");
        }
    }

    /**
     * Provisions a standard test user account for development verification.
     */
    private void injectTestUser() {
        String testEmail = "john@example.com";

        if (!userRepository.existsByEmail(testEmail)) {
            log.info("   -> Injecting Test User Identity: {}", PrivacyHelper.maskEmail(testEmail));

            Role userRole = roleRepository.findByName(UserRole.ROLE_USER)
                    .orElseThrow(() -> new IllegalStateException("Critical Failure: ROLE_USER not found"));

            User testUser = User.builder()
                    .email(testEmail)
                    .name("John")
                    .password(passwordEncoder.encode("simpleone")) 
                    .enabled(true)
                    .provider(Provider.LOCAL)
                    .roles(Set.of(userRole))
                    .build();

            userRepository.save(testUser);
            log.info("   -> Test User Identity successfully persistent.");
        }
    }
}
