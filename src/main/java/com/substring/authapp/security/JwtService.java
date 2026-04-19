package com.substring.authapp.security;

import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * <h1>JWT Operations Engine</h1>
 *
 * <p>Responsible for the lifecycle of JSON Web Tokens (JWT), providing utilities for 
 * token generation, cryptographic parsing, and validation. It centralizes all 
 * security-sensitive logic related to identity token processing.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Cryptographic Provisioning:</b> Initializes signing keys from secure configurations.
 * 2. <b>Token Issuance:</b> Generates signed Access and Refresh tokens with specific claims.
 * 3. <b>Integrity Verification:</b> Parses and validates tokens against tampering and expiration.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This service utilizes the <b>jjwt</b> library to implement the <b>HMAC SHA-512</b> 
 * algorithm for signing tokens. It integrates with Spring's {@code @Value} to 
 * load security configurations and provides the cryptographic foundation for 
 * the {@link JwtAuthenticationFilter}.</p>
 *
 * <p><b>Design Rationale:</b>
 * Employs a <b>Dual-Token Architecture</b>:
 * <ul>
 *   <li><b>Access Tokens:</b> Short-lived and stateless, minimizing the impact of 
 *       token theft.</li>
 *   <li><b>Refresh Tokens:</b> Long-lived and stateful (linked to database), enabling 
 *       precise revocation control and token rotation.</li>
 * </ul>
 * This balance ensures high performance through statelessness while maintaining 
 * the ability to terminate compromised sessions.
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.security.JwtAuthenticationFilter
 */
@Service
@Getter
public class JwtService {

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    /**
     * Initializes the service with cryptographic parameters.
     *
     * <p><b>Behind the Scenes:</b>
     * The {@link SecretKey} is derived from the configured secret string using 
     * {@code Keys.hmacShaKeyFor()}. This key is then used for all subsequent 
     * signing and verification operations, ensuring consistency across the application.</p>
     *
     * @param secretKey The raw HMAC secret (must be at least 64 bytes for HS512).
     * @param accessTtlSeconds Expiration time for access tokens.
     * @param refreshTtlSeconds Expiration time for refresh tokens.
     * @param issuer The entity that issues the tokens (identifies the server).
     */
    public JwtService(
            @Value("${security.jwt.secret}") String secretKey,
            @Value("${security.jwt.acess-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer) {
        
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    /**
     * Creates a signed Access Token for user authorization.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Collects user metadata (UUID, email, roles).
     * 2. Sets standard claims: {@code sub} (Subject), {@code iss} (Issuer), {@code iat} (Issued At), and {@code exp} (Expiration).
     * 3. Adds custom claims: {@code email}, {@code roles}, and {@code typ} (set to 'access').
     * 4. Signs the payload using the HS512 algorithm and the private secret key.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * The inclusion of roles in the Access Token allows the {@link JwtAuthenticationFilter} 
     * to populate authorities without an additional database query for every request, 
     * significantly improving API throughput.</p>
     *
     * @param user The user for whom the token is generated.
     * @return A compact, signed JWT string.
     */
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles() == null ? List.of() :
                user.getRoles().stream().map(role -> role.getName().toString()).collect(Collectors.toList());

        return Jwts.builder()
                .id(UUID.randomUUID().toString()) // Unique ID for each access token (JTI)
                .subject(user.getId().toString()) // The Subject claim is the persistent user identifier
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTtlSeconds))) // Short expiration for security
                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles", roles,
                        "typ", "access" // Custom claim to distinguish token type
                ))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Creates a signed Refresh Token for session extension.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Uses the provided JTI (JWT ID) which corresponds to a database record.
     * 2. Sets the {@code typ} claim to 'refresh' to prevent misuse as an access token.
     * 3. Signs the token with a longer expiration period.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Refresh tokens contain minimal information. This reduces the risk of sensitive 
     * data exposure if a refresh token (which has a longer life) is intercepted.</p>
     *
     * @param user The user.
     * @param jti The unique identifier linked to the persistent token record.
     * @return A signed JWT string.
     */
    public String generateRefreshToken(User user, String jti) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTtlSeconds))) // Longer expiration (e.g., 7-30 days)
                .claim("typ", "refresh") // Custom claim to ensure this cannot be used as an access token
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Parses and cryptographically validates a JWT string.
     *
     * <p><b>Behind the Scenes:</b>
     * The parser verifies the HMAC signature using the service's secret key. If the 
     * token was tampered with, expired, or signed with a different key, the library 
     * will throw an appropriate {@link JwtException}.</p>
     *
     * @param token The raw JWT string.
     * @return A {@link Jws} object containing the verified claims.
     * @throws ExpiredJwtException If the current time is after the {@code exp} claim.
     * @throws JwtException If the token is malformed or the signature is invalid.
     */
    public Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }

    /**
     * Verifies if the token is a designated 'access' token.
     *
     * @param token The JWT string.
     * @return {@code true} if the {@code typ} claim is 'access'.
     */
    public boolean isAccessToken(String token) {
        return "access".equals(parse(token).getPayload().get("typ"));
    }

    /**
     * Verifies if the token is a designated 'refresh' token.
     *
     * @param token The JWT string.
     * @return {@code true} if the {@code typ} claim is 'refresh'.
     */
    public boolean isRefreshToken(String token) {
        return "refresh".equals(parse(token).getPayload().get("typ"));
    }

    /**
     * Extracts the User ID from the token's subject claim.
     *
     * @param token The JWT string.
     * @return The User's UUID.
     */
    public UUID getUseriD(String token) {
        return UUID.fromString(parse(token).getPayload().getSubject());
    }

    /**
     * Extracts the JWT ID (JTI) from the token.
     *
     * @param token The JWT string.
     * @return The JTI string.
     */
    public String getJti(String token) {
        return parse(token).getPayload().getId();
    }
}
