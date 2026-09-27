package com.substring.authapp.security;

import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JwtService Unit Tests")
class JwtServiceTest {

    private JwtService jwtService;
    private final String secret = "9a65609d57a2f5f190e3f8a04b732629b3a4a9844f6f8972827179929f270929";
    private final long accessTtl = 3600;
    private final long refreshTtl = 86400;
    private final String issuer = "AuthAppTest";

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(secret, accessTtl, refreshTtl, issuer);
    }

    @Test
    @DisplayName("Should generate a valid access token")
    void generateAccessToken_ShouldReturnValidToken() {
        User user = createMockUser();
        String token = jwtService.generateAccessToken(user);

        assertThat(token).isNotBlank();
        
        Jws<Claims> claims = jwtService.parse(token);
        assertThat(claims.getPayload().getSubject()).isEqualTo(user.getId().toString());
        assertThat(claims.getPayload().get("email")).isEqualTo(user.getEmail());
        assertThat(claims.getPayload().get("typ")).isEqualTo("access");
        assertThat(claims.getPayload().get("version", Integer.class)).isEqualTo(0);
    }

    @Test
    @DisplayName("Should correctly identify token types")
    void tokenTypeChecks_ShouldReturnCorrectBooleans() {
        User user = createMockUser();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, UUID.randomUUID().toString());

        assertThat(jwtService.isAccessToken(accessToken)).isTrue();
        assertThat(jwtService.isAccessToken(refreshToken)).isFalse();
        
        assertThat(jwtService.isRefreshToken(refreshToken)).isTrue();
        assertThat(jwtService.isRefreshToken(accessToken)).isFalse();
    }

    @Test
    @DisplayName("Should throw SignatureException when token is tampered")
    void parse_WithTamperedToken_ShouldThrowException() {
        User user = createMockUser();
        String token = jwtService.generateAccessToken(user);
        
        // Tamper with the signature (last part of JWT)
        String tamperedToken = token.substring(0, token.length() - 5) + "abcde";

        assertThatThrownBy(() -> jwtService.parse(tamperedToken))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    @DisplayName("Should throw ExpiredJwtException when token is expired")
    void parse_WithExpiredToken_ShouldThrowException() {
        // We create an expired token manually using the same key and algorithm
        // Note: JwtService uses HS256 based on the 64 char hex key.
        
        String expiredToken = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .expiration(new Date(System.currentTimeMillis() - 10000)) // 10 seconds ago
                .signWith(jwtService.getKey(), Jwts.SIG.HS256)
                .compact();

        assertThatThrownBy(() -> jwtService.parse(expiredToken))
                .isInstanceOf(ExpiredJwtException.class);
    }

    private User createMockUser() {
        UUID id = UUID.randomUUID();
        Role role = Role.builder().name(UserRole.ROLE_USER).build();
        return User.builder()
                .id(id)
                .email("test@example.com")
                .roles(new HashSet<>(List.of(role)))
                .enabled(true)
                .build();
    }
}
