package com.substring.authapp.security;

import com.substring.authapp.entities.User;
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
 * 3. <b>Identification:</b> Extracts the user identity (UUID) and synchronizes with the {@link com.substring.authapp.repositories.UserRepository}.
 * 4. <b>Authorization:</b> Maps entity-level roles to {@link org.springframework.security.core.GrantedAuthority} objects.
 * 5. <b>Contextualization:</b> Populates the {@link org.springframework.security.core.context.SecurityContextHolder} to authenticate the request thread.
 * </p>
 *
 * <p><b>Behind the Scenes (Filter Chain Interaction):</b>
 * This component is injected <b>before</b> the standard {@code UsernamePasswordAuthenticationFilter} in the 
 * {@link org.springframework.security.web.SecurityFilterChain}. It acts as a manual <b>Short-Circuit</b> 
 * for stateless requests. If a valid token is present, the {@link org.springframework.security.core.context.SecurityContextHolder} 
 * is populated, effectively bypassing the need for subsequent credential-based authentication steps for that specific request.</p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * By extending {@link org.springframework.web.filter.OncePerRequestFilter}, the application ensures 
 * that expensive cryptographic validation and database lookups happen exactly once per request. 
 * The <b>Short-Circuit</b> mechanism allows the security context to be established 
 * instantly for authenticated requests, reducing latency and avoiding redundant 
 * authentication logic in downstream filters. This ensures that valid token-holders 
 * are "fast-tracked" through the security pipeline.
 * </p>
 * 
 * @author Gemini CLI
 * @see JwtService
 * @see com.substring.authapp.repositories.UserRepository
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // ===================================================================================
    // SECTION 2: Constructor (Dependency Injection)
    // ===================================================================================

    public JwtAuthenticationFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    // ===================================================================================
    // SECTION 3: Filter Implementation (Core Logic)
    // ===================================================================================

    /**
     * Executes the core JWT validation and authentication logic.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Extraction:</b> Extracts the {@code Authorization} header and verifies the {@code Bearer } prefix.
     * 2. <b>Type Validation:</b> Isolates the raw token and confirms it is an 'access' type token via {@link JwtService}.
     * 3. <b>Signature Verification:</b> Parses the token to extract the subject (User UUID) while verifying the signature.
     * 4. <b>Context Population:</b> Retrieves the {@link com.substring.authapp.entities.User} entity and populates the {@link SecurityContextHolder}.
     * </p>
     *
     * <p><b>Behind the Scenes (Short-Circuit Logic):</b>
     * The method performs an <b>Early Exit</b> if no Bearer token is found or if the token is 
     * not of type 'ACCESS'. If a valid token is processed, the {@link SecurityContextHolder} 
     * is populated with a {@link UsernamePasswordAuthenticationToken}. This population 
     * acts as the <b>Short-Circuit</b>, as subsequent filters (like {@code FilterSecurityInterceptor}) 
     * will see an already authenticated principal and permit access without further challenges.</p>
     *
     * @param request The incoming HTTP request.
     * @param response The outgoing HTTP response.
     * @param filterChain The chain of subsequent filters to execute.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {

        // PHASE 1: Header Extraction
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);

            try {
                // PHASE 2: Token Type & Signature Validation (Short-Circuit)
                if (!jwtService.isAccessToken(token)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                Jws<Claims> claims = jwtService.parse(token);
                Claims payload = claims.getPayload();
                String userId = payload.getSubject();
                UUID userUUID = UUID.fromString(userId);

                // PHASE 3: Identity Resolution & Security Context Population
                userRepository.findById(userUUID).ifPresent(user -> {
                    Integer tokenVersion = payload.get("version", Integer.class);
                    if (user.isEnabled() && tokenVersion != null && tokenVersion == user.getTokenVersion()) {
                        List<GrantedAuthority> authorities = user.getRoles() == null ? List.of() : 
                            user.getRoles().stream()
                                .map(role -> new SimpleGrantedAuthority(role.getName().toString()))
                                .collect(Collectors.toList());

                        // CRITICAL FIX: Store the full 'user' object as the principal instead of just user.getEmail()
                        // This allows @AuthenticationPrincipal User currentUser to work in controllers.
                        UsernamePasswordAuthenticationToken authentication = 
                            new UsernamePasswordAuthenticationToken(user, null, authorities);

                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        if (SecurityContextHolder.getContext().getAuthentication() == null) {
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
                    }
                });
            } catch (ExpiredJwtException e) {
                request.setAttribute("error", "Token has expired");
                logger.warn("JWT Token expired: {}", e.getMessage());
            } catch (Exception e) {
                request.setAttribute("error", "Token is not valid");
                logger.error("JWT validation error: {}", e.getMessage());
            }
        }

        // PHASE 4: Chain Continuation
        filterChain.doFilter(request, response);
    }

    // ===================================================================================
    // SECTION 4: Filter Routing (Overrides)
    // ===================================================================================

    /**
     * <h1>Bypass Strategy</h1>
     * 
     * <p>Determines whether the current request should bypass this filter.</p>
     *
     * <p><b>Design Rationale:</b>
     * Public endpoints (e.g., login, signup, forget-password) are excluded from JWT 
     * validation to allow unauthenticated users to initiate identity-related actions.</p>
     *
     * @param request The current HTTP request.
     * @return {@code true} if the request targets an authentication endpoint.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}