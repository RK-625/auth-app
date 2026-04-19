package com.substring.authapp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.ApiError;
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
 * 1. <b>Password Hashing:</b> Defines the encoding strategy for user credentials.
 * 2. <b>Policy Definition:</b> Sets up CORS, CSRF, and Session management policies.
 * 3. <b>Authorization Mapping:</b> Specifies which endpoints are public and which require specific roles.
 * 4. <b>Filter Orchestration:</b> Injects custom filters (Rate Limiter, JWT) into the standard Spring Security pipeline.</p>
 *
 * <p><b>Architecture Component Map (The Ecosystem):</b>
 * <ul>
 *   <li><b>{@link RateLimitingFilter}</b>: 
 *       The "Network Bouncer." Sits at the very front of the chain to block DDoS and Brute Force attacks (HTTP 429) before any CPU/Database resources are consumed.</li>
 *   <li><b>{@link JwtAuthenticationFilter}</b>: 
 *       The "Session Validator." Parses Bearer tokens to establish a stateless security context for authorized API requests.</li>
 *   <li><b>{@code UsernamePasswordAuthenticationFilter}</b>: 
 *       The default Spring filter that processes traditional form-based logins. Our custom filters are injected <i>before</i> this.</li>
 * </ul>
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This configuration leverages the {@code SecurityFilterChain} bean to override default security settings.
 * It interacts with the {@code FilterSecurityInterceptor} to perform authorization checks and uses
 * {@code SessionCreationPolicy.STATELESS} (conceptually) to ensure no JSESSIONID is maintained on the server.</p>
 *
 * <p><b>Design Rationale:</b>
 * By choosing a stateless architecture with JWTs, we ensure the application can scale horizontally
 * without session affinity. Placing the {@link JwtAuthenticationFilter} before the standard login filter
 * ensures that token-based requests are processed with high priority.</p>
 *
 * @author Gemini CLI
 * @version 1.0
 * @see JwtAuthenticationFilter
 * @see org.springframework.security.web.SecurityFilterChain
 * @see BCryptPasswordEncoder
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final RateLimitingFilter rateLimitingFilter;
    /**
     * Provides the primary password hashing mechanism for the application.
     *
     * <p><b>Behind the Scenes:</b>
     * Utilizes {@link BCryptPasswordEncoder} which implements a slow hashing algorithm with a built-in salt.
     * When {@code passwordEncoder.matches()} is called, it extracts the salt from the stored hash to verify
     * the raw password.</p>
     *
     * <p><b>Design Rationale:</b>
     * BCrypt is chosen for its adaptive nature and resistance to rainbow table and brute-force attacks.
     * Its computational cost mitigates the impact of database leaks.</p>
     *
     * @return A {@link PasswordEncoder} instance using the BCrypt algorithm.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Defines the HTTP security filter chain that manages all web-level security.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. <b>CSRF:</b> Disabled to accommodate stateless API consumers (mobile/React).
     * 2. <b>CORS:</b> Configured to permit cross-origin requests from the frontend application.
     * 3. <b>Session:</b> Set to {@code IF_REQUIRED} to support the OAuth2 login state while maintaining an otherwise stateless API.
     * 4. <b>Access Control:</b> Maps URL patterns to authentication requirements (permitAll vs authenticated).
     * 5. <b>Custom Filters:</b> Injects the {@link JwtAuthenticationFilter} to handle Bearer token extraction.</p>
     *
     * <p><b>Behind the Scenes:</b>
     * This method builds a {@code DefaultSecurityFilterChain}. The order of filters is critical;
     * {@code jwtAuthenticationFilter} is placed before {@code UsernamePasswordAuthenticationFilter}
     * to intercept JWTs before traditional form-based login logic triggers.</p>
     *
     * <p><b>Design Rationale:</b>
     * Using a centralized filter chain configuration ensures that security policies are applied consistently
     * across all endpoints. The use of an {@code AuthenticationEntryPoint} ensures that 401 responses
     * are standardized and JSON-formatted for API clients.</p>
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
                            "/error"
                        ).permitAll()
                        // 2. Role-based access control for administrative paths
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
                .addFilterBefore(rateLimitingFilter,JwtAuthenticationFilter.class)
                // Inject the custom JWT filter BEFORE the standard UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // Standardized 401 Unauthorized response for API consumers
                .exceptionHandling(e -> e.authenticationEntryPoint((req, rsp, ex) -> {
                    rsp.setStatus(401);
                    rsp.setContentType("application/json");
                    
                    String message = (String) req.getAttribute("error");
                    if (message == null) message = "Unauthorized access";
                    
                    ApiError error = ApiError.of(401, "Unauthorized", message, req.getRequestURI());
                    rsp.getWriter().write(objectMapper.writeValueAsString(error));
                }));

        return http.build();
    }

    /**
     * Exposes the {@link AuthenticationManager} as a Spring Bean.
     *
     * <p><b>Behind the Scenes:</b>
     * The {@code AuthenticationManager} is the primary interface for manual authentication.
     * It delegates to a list of {@code AuthenticationProvider}s (like {@code DaoAuthenticationProvider})
     * which in turn use {@code UserDetailsService} to load user data.</p>
     *
     * <p><b>Design Rationale:</b>
     * Exposing this bean allows the {@link AuthService} to programmatically authenticate users
     * during the standard login flow, providing a clean separation between security configuration and business logic.</p>
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
