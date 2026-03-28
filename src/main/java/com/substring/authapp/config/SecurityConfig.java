package com.substring.authapp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.ApiError;
import com.substring.authapp.security.JwtAuthenticationFilter;
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
 * Main security configuration class for the application.
 * Manages the security filter chain, endpoint access, and authentication providers.
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    /**
     * Standard encoder for secure password hashing.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configuration for the primary security filter chain.
     * Defines the stateless session policy, CORS/CSRF settings, and request authorization rules.
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
     * Exposes the AuthenticationManager as a bean for manual authentication in controllers.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
