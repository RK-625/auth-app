package com.substring.authapp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.common.ApiError;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.security.JwtAuthenticationFilter;
import com.substring.authapp.security.RateLimitingFilter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * <h1>Security Configuration Center</h1>
 *
 * <p>This class serves as the central hub for the application's security architecture.
 * It configures Spring Security's {@code SecurityFilterChain}, which is a chain of
 * Servlet Filters that intercept every incoming HTTP request to apply security rules.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Password Hashing:</b> Defines the encoding strategy for user credentials using {@link BCryptPasswordEncoder}.
 * 2. <b>Policy Definition:</b> Sets up CORS, CSRF (Disabled), and Session management policies.
 * 3. <b>Authorization Mapping:</b> Specifies which endpoints are public and which require specific roles.
 * 4. <b>Filter Orchestration:</b> Injects custom filters (Rate Limiter, JWT) into the standard Spring Security pipeline.
 * </p>
 * 
 * <p><b>Behind the Scenes (Security Handshake):</b>
 * This configuration manages the complex <b>Authentication Handshake</b>. The 
 * {@link JwtAuthenticationFilter} is injected <b>before</b> the standard 
 * {@code UsernamePasswordAuthenticationFilter} to handle stateless Bearer tokens. 
 * Simultaneously, the {@link RateLimitingFilter} is placed at the absolute front 
 * of the chain to provide an <b>Immediate Short-Circuit</b> for DDoS protection. 
 * The {@link org.springframework.security.authentication.AuthenticationManager} 
 * acts as the bridge between the {@link com.substring.authapp.services.AuthService} 
 * and the {@link com.substring.authapp.security.CustomUserDetailService}, 
 * facilitating the <b>Credential Validation Handshake</b>.</p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * The system employs a <b>Hybrid "Stateful Stateless"</b> model. While the API is 
 * conceptually stateless using JWTs, the authentication flow leverages a persistent 
 * <b>Refresh Token</b> (stored in the database) to provide a "Session Kill-Switch," 
 * combining the scalability of JWTs with the control of stateful sessions. 
 * Placing the {@link RateLimitingFilter} and {@link JwtAuthenticationFilter} 
 * early ensures that resource-intensive logic is only reached for 
 * authorized, non-abusive traffic.
 * </p>
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final RateLimitingFilter rateLimitingFilter;
    private final MessageHelper messageHelper;

    // ===================================================================================
    // SECTION 2: Password Encoding (Cryptography)
    // ===================================================================================

    /**
     * <h1>Password Encoding Authority</h1>
     * 
     * <p>Provides the primary password hashing mechanism for the application.</p>
     *
     * <p><b>Behind the Scenes (Hashing Handshake):</b>
     * Utilizes {@link BCryptPasswordEncoder} which implements a slow hashing algorithm with a built-in salt.
     * During the <b>Authentication Handshake</b>, the {@code DaoAuthenticationProvider} 
     * utilizes this bean to compare raw incoming passwords against the database-stored 
     * hashes, ensuring the <b>Salt Extraction Handshake</b> is performed correctly.</p>
     *
     * <p><b>Design Rationale (The "Why"):</b>
     * BCrypt is chosen for its adaptive nature and resistance to rainbow table and brute-force attacks.
     * Its computational cost mitigates the impact of database leaks.
     * </p>
     *
     * @return A {@link PasswordEncoder} instance using the BCrypt algorithm.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ===================================================================================
    // SECTION 3: Security Filter Chain (The "Firewall")
    // ===================================================================================

    /**
     * <h1>Security Filter Chain Orchestrator</h1>
     * 
     * <p>Defines the HTTP security filter chain that manages all web-level security.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. <b>CSRF:</b> Disabled to accommodate stateless API consumers (mobile/React).
     * 2. <b>CORS:</b> Configured to permit cross-origin requests from the frontend application.
     * 3. <b>Session:</b> Set to {@code IF_REQUIRED} to support the OAuth2 login state while maintaining an otherwise stateless API.
     * 4. <b>Access Control:</b> Maps URL patterns to authentication requirements (permitAll vs authenticated).
     * 5. <b>Custom Filters:</b> Injects the {@link JwtAuthenticationFilter} to handle Bearer token extraction.
     * </p>
     *
     * <p><b>Behind the Scenes (Filter Sequence Handshake):</b>
     * This method builds a {@code DefaultSecurityFilterChain}. The order of filters is critical:
     * <ul>
     *   <li>{@link RateLimitingFilter} is injected <b>before</b> {@link JwtAuthenticationFilter} 
     *       to protect the system from resource exhaustion at the absolute front-line.</li>
     *   <li>{@link JwtAuthenticationFilter} is placed <b>before</b> {@code UsernamePasswordAuthenticationFilter} 
     *       to intercept and validate JWTs before traditional login logic is triggered.</li>
     * </ul>
     * This establishes an <b>Order-of-Operations Handshake</b> where security layers 
     * are peeled back from the least to most resource-intensive.</p>
     *
     * <p><b>Design Rationale (The "Why"):</b>
     * Using a centralized filter chain configuration ensures that security policies are applied consistently
     * across all endpoints. The use of an {@code AuthenticationEntryPoint} ensures that 401 responses
     * are standardized and JSON-formatted for API clients.
     * </p>
     *
     * @param http The {@link HttpSecurity} builder.
     * @return The configured {@link SecurityFilterChain}.
     * @throws Exception If configuration encounters an error.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable) // CSRF is disabled as we use stateless JWTs
                .cors(Customizer.withDefaults())
                // Stateless session management: No HTTP sessions are created or used by Spring Security
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(authorize -> authorize
                        // 1. Publicly accessible endpoints (Auth, OAuth2, Error)
                        .requestMatchers(
                            "/api/v1/auth/**",
                            "/oauth2/**",
                            "/login/**",
                            "/error",
                            "/actuator/health"
                        ).permitAll()
                        // 2. Role-based access control for administrative paths
                        .requestMatchers("/actuator/**").hasRole("ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN", "ROOT")
                        .requestMatchers("/api/v1/root/**").hasRole("ROOT")
                        // 3. Protected endpoints requiring any valid authentication
                        .requestMatchers("/api/v1/update/user/**").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        // Handle successful social login redirection and user synchronization
                        .successHandler(authenticationSuccessHandler)
                        .failureHandler((req, res, ex) -> {
                            logger.error("OAuth2 Login failed: {}", ex.getMessage());
                            res.sendRedirect("/api/v1/auth/oauth2/failure");
                        })
                )
                .logout(AbstractHttpConfigurer::disable) // Handled manually in AuthController
                // Inject the custom JWT filter BEFORE the standard UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // Inject the rate limiting filter BEFORE the JWT filter (by also placing it before UPAF)
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                // Standardized 401 Unauthorized response for API consumers
                .exceptionHandling(e -> e.authenticationEntryPoint((req, rsp, ex) -> {
                    rsp.setStatus(401);
                    rsp.setContentType("application/json");
                    
                    String message = (String) req.getAttribute("error");
                    if (message == null) message = messageHelper.getMessage("system.error.unauthorized");
                    
                    ApiError error = ApiError.of(401, "Unauthorized", message, req.getRequestURI());
                    rsp.getWriter().write(objectMapper.writeValueAsString(error));
                }));

        return http.build();
    }

    // ===================================================================================
    // SECTION 4: Auth Management (Beans)
    // ===================================================================================

    /**
     * Exposes the {@link AuthenticationManager} as a Spring Bean.
     *
     * <p><b>Behind the Scenes (Authentication Handshake):</b>
     * The {@code AuthenticationManager} is the primary interface for manual authentication.
     * It delegates to a list of {@code AuthenticationProvider}s (like {@code DaoAuthenticationProvider})
     * which in turn use {@code UserDetailsService} to load user data.</p>
     *
     * <p><b>Design Rationale (The "Why"):</b>
     * Exposing this bean allows the {@link com.substring.authapp.services.AuthService} to programmatically 
     * authenticate users during the standard login flow, providing a clean separation 
     * between security configuration and business logic.</p>
     *
     * @param configuration The {@link AuthenticationConfiguration} used to retrieve the manager.
     * @return The configured {@link AuthenticationManager}.
     * @throws Exception If retrieval fails.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
