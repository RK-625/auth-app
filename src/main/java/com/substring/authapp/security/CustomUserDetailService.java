package com.substring.authapp.security;

import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


/**
 * <h1>Spring Security User Adapter (The Truth Provider)</h1>
 *
 * <p>Implements the {@link UserDetailsService} interface to provide a custom strategy 
 * for loading user-specific data from the application's database. This service is 
 * the bridge between the persistent {@link com.substring.authapp.entities.User} entity 
 * and Spring Security's internal {@link UserDetails} contract.</p>
 *
 * <p><b>Behind the Scenes (The Handshake):</b>
 * This service is a primary collaborator for the <b>{@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}</b>. 
 * During the {@code authenticate()} flow:
 * <ol>
 *   <li>The provider calls {@link #loadUserByUsername(String)} with the user's email.</li>
 *   <li>This service retrieves the entity from the {@link UserRepository}.</li>
 *   <li>The provider then extracts the <b>stored hash</b> from the returned {@code UserDetails}.</li>
 *   <li>Finally, the provider uses a {@code PasswordEncoder} to verify the incoming raw password.</li>
 * </ol>
 * </p>
 *
 * <p><b>Security Note (Anti-Enumeration):</b>
 * To mitigate "User Enumeration" attacks, this service is designed to throw a 
 * generic {@link BadCredentialsException} if a user is not found. This prevents 
 * attackers from determining which emails are registered based on timing or 
 * error message differences.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * By adapting our JPA entity to the {@code UserDetails} interface, we allow 
 * Spring Security to handle the complex logic of password verification and 
 * account status checks (enabled/locked) while maintaining control over 
 * our data schema.</p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.entities.User
 * @see org.springframework.security.core.userdetails.UserDetailsService
 * @see org.springframework.security.authentication.dao.DaoAuthenticationProvider
 */
@Service
@AllArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final UserRepository userRepository;
    private final MessageHelper messageHelper;

    // ===================================================================================
    // SECTION 2: UserDetails Implementation (Public)
    // ===================================================================================

    /**
     * Retrieves a user entity from the database using their email address.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Receives the identifier string (email) from the authentication provider.
     * 2. Queries the {@link UserRepository} for a matching user.
     * 3. Returns the {@link UserDetails} object or throws a security-aware exception.
     * </p>
     *
     * <p><b>Behind the Scenes (Handshake Resolution):</b>
     * If the user is not found, we throw a {@link BadCredentialsException} rather 
     * than the standard {@link UsernameNotFoundException}. This is a security 
     * best practice to prevent "User Enumeration" attacks, where an attacker 
     * could verify the existence of an account by observing different error messages.</p>
     *
     * @param email The user's email address.
     * @return A fully populated {@link UserDetails} instance.
     * @throws BadCredentialsException If no user is found with the provided email.
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email).orElseThrow(()-> new BadCredentialsException(messageHelper.getMessage("auth.login.invalid_credentials")));
    }
}
