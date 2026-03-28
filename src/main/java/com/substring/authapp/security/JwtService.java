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
    private final long refereshTtlSeconds;
    private final String issuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secretKey,
            @Value("${security.jwt.acess-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refereshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer) {
        
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refereshTtlSeconds = refereshTtlSeconds;
        this.issuer = issuer;
    }

    /**
     * Generates a short-lived access token containing user identity and roles.
     */
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles() == null ? List.of() :
                user.getRoles().stream().map(role -> role.getName().toString()).collect(Collectors.toList());

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTtlSeconds)))
                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles", roles,
                        "typ", "access"
                ))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Generates a long-lived refresh token for renewing access tokens.
     */
    public String generateRefereshToken(User user, String jti) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refereshTtlSeconds)))
                .claim("typ", "refresh")
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Parses and validates a JWT string against the signing key.
     */
    public Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }

    /**
     * Checks if the provided token is an access token.
     */
    public boolean isAccessToken(String token) {
        return "access".equals(parse(token).getPayload().get("typ"));
    }

    /**
     * Checks if the provided token is a refresh token.
     */
    public boolean isRefreshToken(String token) {
        return "refresh".equals(parse(token).getPayload().get("typ"));
    }

    /**
     * Extracts the User ID from the token's subject claim.
     */
    public UUID getUseriD(String token) {
        return UUID.fromString(parse(token).getPayload().getSubject());
    }

    /**
     * Extracts the unique Token Identifier (JTI).
     */
    public String getJti(String token) {
        return parse(token).getPayload().getId();
    }
}
