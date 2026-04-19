package com.substring.authapp.security;

import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * <h1>JWT Stateless Authentication Guardian</h1>
 *
 * <p>The primary security interceptor for the REST API layer. This filter is responsible for
 * intercepting every incoming HTTP request to extract, parse, and validate JSON Web Tokens (JWT)
 * before the request is allowed to proceed to the controller level.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Extraction:</b> Isolates the JWT from the {@code Authorization} bearer header.
 * 2. <b>Validation:</b> Verifies the cryptographic signature and ensures the token is of type {@code ACCESS}.
 * 3. <b>Identification:</b> Extracts the user identity (UUID) and synchronizes with the {@link UserRepository}.
 * 4. <b>Authorization:</b> Maps entity-level roles to {@link GrantedAuthority} objects.
 * 5. <b>Contextualization:</b> Populates the {@link SecurityContextHolder} to authenticate the request thread.
 * </p>
 *
 * <p><b>Behind the Scenes (Filter Chain Position):</b>
 * This component is injected <b>before</b> the standard {@code UsernamePasswordAuthenticationFilter} in the 
 * {@link org.springframework.security.web.SecurityFilterChain}. It acts as a manual "short-circuit" 
 * for stateless requests. If a valid token is present, the {@link SecurityContextHolder} is populated 
 * with a {@link UsernamePasswordAuthenticationToken}, effectively bypassing the need for subsequent 
 * credential-based authentication steps for that specific request.</p>
 *
 * <p><b>Design Rationale (Stateless Security):</b>
 * By extending {@link OncePerRequestFilter}, the application ensures that expensive cryptographic 
 * validation and database lookups happen exactly once per request. This architecture supports 
 * high-concurrency environments by eliminating the need for server-side HTTP sessions (JSESSIONID).
 * </p>
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    public JwtAuthenticationFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    /**
     * Executes the core JWT validation and authentication logic.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Extracts the {@code Authorization} header and verifies the {@code Bearer } prefix.
     * 2. Isolates the raw token and confirms it is an 'access' type token via {@link JwtService}.
     * 3. Parses the token to extract the subject (User UUID) while verifying the cryptographic signature.
     * 4. Retrieves the {@link User} entity from the database to verify existence and activity.
     * 5. Maps the user's roles to {@link GrantedAuthority} objects.
     * 6. Populates the {@link SecurityContextHolder} with a new {@link UsernamePasswordAuthenticationToken}.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * The {@link SecurityContextHolder} uses a {@code ThreadLocal} strategy by default. 
     * This means the authentication state is isolated to the current request thread 
     * and is automatically cleared when the request completes, enforcing statelessness.
     * </p>
     *
     * @param request The incoming HTTP request.
     * @param response The outgoing HTTP response.
     * @param filterChain The chain of subsequent filters to execute.
     * @throws ServletException If a servlet-level error occurs.
     * @throws IOException If an I/O error occurs during filter execution.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {

        // 1. Extract the Authorization header from the request
        String header = request.getHeader("Authorization");

        // 2. Validate the header structure (must start with 'Bearer ')
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);

            try {
                // 3. Ensure the token is a designated 'access' token, not a refresh token
                if (!jwtService.isAccessToken(token)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                // 4. Parse and cryptographically verify the token's signature
                Jws<Claims> claims = jwtService.parse(token);
                Claims payload = claims.getPayload();
                String userId = payload.getSubject();
                UUID userUUID = UUID.fromString(userId);

                // 5. Look up the user in the database to ensure the account still exists and is active
                userRepository.findById(userUUID).ifPresent(user -> {
                    if (user.isEnabled()) {
                        // 6. Map user roles to Spring Security GrantedAuthority objects
                        List<GrantedAuthority> authorities = user.getRoles() == null ? List.of() : 
                            user.getRoles().stream()
                                .map(role -> new SimpleGrantedAuthority(role.getName().toString()))
                                .collect(Collectors.toList());

                        // 7. Construct the Authentication object for the security context
                        UsernamePasswordAuthenticationToken authentication = 
                            new UsernamePasswordAuthenticationToken(user.getEmail(), null, authorities);

                        // 8. Attach request-specific details (IP, Session ID) to the authentication
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        // 9. Finalize the authentication by setting it in the thread-local SecurityContext
                        if (SecurityContextHolder.getContext().getAuthentication() == null) {
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
                    }
                });
            } catch (ExpiredJwtException e) {
                // Specific handling for expired tokens to provide clearer error feedback
                request.setAttribute("error", "Token has expired");
                logger.warn("JWT Token expired: {}", e.getMessage());
            } catch (Exception e) {
                // Generic handling for any other validation failures (malformed token, wrong signature)
                request.setAttribute("error", "Token is not valid");
                logger.error("JWT validation error: {}", e.getMessage());
            }
        }

        // 10. Continue the filter chain regardless of whether a token was found/validated
        filterChain.doFilter(request, response);
    }

    /**
     * Determines whether the current request should bypass this filter.
     *
     * <p><b>Design Rationale:</b>
     * Public endpoints (e.g., login, signup, forget-password) are excluded from JWT 
     * validation to allow unauthenticated users to initiate identity-related actions. 
     * This reduces overhead for endpoints that are explicitly marked as {@code permitAll()} 
     * in the {@code SecurityConfig}.
     * </p>
     *
     * @param request The current HTTP request.
     * @return {@code true} if the request targets an authentication endpoint.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip authentication filter for auth endpoints as they are permitAll
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}
