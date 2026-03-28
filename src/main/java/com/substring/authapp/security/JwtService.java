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
 * Service for generating, parsing, and validating JSON Web Tokens (JWT).
 * Manages both short-lived access tokens and long-lived refresh tokens.
 */
@Service
@Getter
public class JwtService {

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

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
     * Generates a short-lived access token containing user identity and roles.
     * Access tokens are used for stateless authentication on every request.
     * 
     * @param user The user entity for whom the token is generated.
     * @return A signed JWT string containing the user ID, email, and roles.
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
     * Generates a long-lived refresh token for renewing access tokens.
     * Refresh tokens contain minimal claims to maximize security and reduce token size.
     * 
     * @param user The user entity for whom the token is generated.
     * @param jti  The unique token identifier used to match the token in the database.
     * @return A signed JWT string containing the user ID and the specific JTI.
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
     * Parses and validates a JWT string against the configured signing key.
     * This method verifies the signature, issuer, and expiration.
     * 
     * @param token The JWT string to parse.
     * @return A Jws object containing the verified claims.
     * @throws io.jsonwebtoken.JwtException if validation fails (expired, malformed, or invalid signature).
     */
    public Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }

    /**
     * Checks if the provided token is specifically an access token.
     * 
     * @param token The JWT string to check.
     * @return true if the token's 'typ' claim is 'access'.
     */
    public boolean isAccessToken(String token) {
        return "access".equals(parse(token).getPayload().get("typ"));
    }

    /**
     * Checks if the provided token is specifically a refresh token.
     * 
     * @param token The JWT string to check.
     * @return true if the token's 'typ' claim is 'refresh'.
     */
    public boolean isRefreshToken(String token) {
        return "refresh".equals(parse(token).getPayload().get("typ"));
    }

    /**
     * Extracts the persistent User ID from the token's subject claim.
     * 
     * @param token The JWT string to extract from.
     * @return The UUID of the user.
     */
    public UUID getUseriD(String token) {
        return UUID.fromString(parse(token).getPayload().getSubject());
    }

    /**
     * Extracts the unique Token Identifier (JTI) from the token.
     * This ID is used to manage token revocation in the database.
     * 
     * @param token The JWT string to extract from.
     * @return The JTI string.
     */
    public String getJti(String token) {
        return parse(token).getPayload().getId();
    }
}
