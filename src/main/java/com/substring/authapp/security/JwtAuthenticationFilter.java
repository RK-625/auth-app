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
 * Filter responsible for intercepting HTTP requests and validating JWT access tokens.
 * If a valid token is present, it populates the SecurityContext with the user's authentication.
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

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip authentication filter for auth endpoints as they are permitAll
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}
