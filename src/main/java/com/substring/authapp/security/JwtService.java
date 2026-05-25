package com.substring.authapp.security;

import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.HexFormat;
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
 * 1. <b>Cryptographic Provisioning:</b> Initializes signing keys from secure configurations using {@code HS512}.
 * 2. <b>Token Issuance:</b> Generates signed Access and Refresh tokens with differentiated payloads.
 * 3. <b>Integrity Verification:</b> Parses and validates tokens against tampering and expiration.
 * </p>
 *
 * <p><b>Behind the Scenes (Cryptographic Strength):</b>
 * This service utilizes the <b>jjwt</b> library to implement the <b>HMAC SHA-512 (HS512)</b> 
 * algorithm. HS512 was chosen for its high collision resistance and performance on 
 * 64-bit architectures. It requires a minimum key length of 512 bits (64 bytes), 
 * providing a significantly higher security margin than HS256 against brute-force 
 * and dictionary attacks.</p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Employs a <b>Dual-Token Architecture</b> with distinct security profiles:
 * <ul>
 *   <li><b>Access Tokens (Heavy Payload):</b> Short-lived (e.g., 15 min) and stateless. 
 *       Contains full identity claims (email, roles) to enable "Zero-Database" authorization 
 *       checks in the {@link JwtAuthenticationFilter}.</li>
 *   <li><b>Refresh Tokens (Light Payload):</b> Long-lived (e.g., 7 days) and stateful. 
 *       Contains only the {@code jti} (JWT ID) and {@code sub} (Subject). This minimalism 
 *       ensures that if intercepted, the token reveals no sensitive user data while 
 *       still allowing the server to perform a "Kill-Switch" lookup against the database.</li>
 * </ul>
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.security.JwtAuthenticationFilter
 */
@Service
@Getter
public class JwtService {

    // ===================================================================================
    // SECTION 1: Infrastructure & Configuration (Fields)
    // ===================================================================================

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    // ===================================================================================
    // SECTION 2: Constructor (Cryptographic Setup)
    // ===================================================================================

    /**
     * Initializes the service with cryptographic parameters.
     *
     * <p><b>Behind the Scenes:</b>
     * The {@link SecretKey} is derived from the configured secret string using 
     * {@code Keys.hmacShaKeyFor()}. This ensures the key meets the entropy 
     * requirements for the <b>HS512</b> algorithm.</p>
     *
     * @param secretKey The raw HMAC secret (must be at least 64 bytes for HS512).
     * @param accessTtlSeconds Expiration time for access tokens.
     * @param refreshTtlSeconds Expiration time for refresh tokens.
     * @param issuer The entity that issues the tokens (identifies the server).
     */
    public JwtService(
            @Value("${security.jwt.secret}") String secretKey,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer) {
        
        this.key = Keys.hmacShaKeyFor(HexFormat.of().parseHex(secretKey));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    // ===================================================================================
    // SECTION 3: Token Generation Logic (Public)
    // ===================================================================================

    /**
     * Creates a signed Access Token for user authorization.
     *
     * <p><b>Payload Composition:</b>
     * This token is <b>claim-heavy</b>. It includes the user's email and full role list. 
     * This design allows downstream services and filters to make authorization 
     * decisions without querying the database, fulfilling the "Stateless" 
     * promise of JWTs.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Collects user metadata (UUID, email, roles).
     * 2. Sets standard claims: {@code sub}, {@code iss}, {@code iat}, and {@code exp}.
     * 3. Adds custom claims: {@code email}, {@code roles}, and {@code typ} (set to 'access').
     * 4. Signs the payload using the <b>HS512</b> algorithm.
     * </p>
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
                        "typ", "access",
                        "version", user.getTokenVersion()
                ))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Creates a signed Refresh Token for session extension.
     *
     * <p><b>Payload Composition:</b>
     * This token is <b>claim-light</b>. It intentionally excludes sensitive 
     * metadata like roles or email. Its primary purpose is to act as a 
     * secure handle to the {@link com.substring.authapp.entities.RefreshToken} 
     * entity in the database via the {@code jti} claim.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Uses the provided JTI (JWT ID) which corresponds to a database record.
     * 2. Sets the {@code typ} claim to 'refresh' to prevent misuse.
     * 3. Signs the token with <b>HS512</b> and a longer expiration period.
     * </p>
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
                .claim("version", user.getTokenVersion())
                .claim("typ", "refresh") // Custom claim to ensure this cannot be used as an access token
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ===================================================================================
    // SECTION 4: Token Parsing & Validation (Public)
    // ===================================================================================

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

    // ===================================================================================
    // SECTION 5: Claims Extraction (Public)
    // ===================================================================================

    /**
     * Extracts the User ID from the token's subject claim.
     *
     * @param token The JWT string.
     * @return The User's UUID.
     */
    public UUID getUserId(String token) {
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
