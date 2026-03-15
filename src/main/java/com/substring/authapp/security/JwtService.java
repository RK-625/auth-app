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
import java.sql.Date;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Getter
public class JwtService  {
    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refereshTtlSeconds;
    private final String issuer;


    public JwtService(
            @Value("${security.jwt.secret}") String secretKey,
            @Value("${security.jwt.acess-ttl-seconds}")long accessTtlSeconds,@Value("${security.jwt.refresh-ttl-seconds}")long refereshTtlSeconds,@Value("${security.jwt.issuer}")  String issuer) {

        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refereshTtlSeconds = refereshTtlSeconds;
        this.issuer = issuer;
    }

    // generate token :
    public String generateAccessToken(User user){
        Instant now = Instant.now();
        List<String> roles = user.getRoles().isEmpty() ? List.of() :
                user.getRoles().stream().map(Role::getName).collect(Collectors.toList());

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(java.util.Date.from(now.plusSeconds(accessTtlSeconds)))
                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles",roles,
                        "typ","access"
                        )
                ).signWith(key, SignatureAlgorithm.HS512).compact();
    }

    // return a referesh jwt token
    // purpose of referesh token is that when the access token is expired
    // regen the access token from referesh toekn of the user
    // this is used to prevent repetitive log - in requests right
    //
    public String generateRefereshToken(User user , String jti){
        Instant now = Instant.now();
        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(java.util.Date.from(now))
                .expiration(java.util.Date.from(now.plusSeconds(refereshTtlSeconds)))
                .claim("typ","refresh")
                .signWith(key,SignatureAlgorithm.HS512).compact();
    }
    // parse the token to get the claims
    public Jws<Claims> parse(String token){
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }
    public boolean isAccessToken(String token){
        Claims c = parse(token).getPayload();
        return c.get("typ").equals("access");
    }
    public boolean isRefreshToken(String token){
        Claims c = parse(token).getPayload();
        return c.get("typ").equals("refresh");
    }
    public UUID getUseriD(String token){
        Claims c = parse(token).getPayload();
        return UUID.fromString(c.getSubject());
    }
    public String getJti(String token){
        return parse(token).getPayload().getId(); 
    }
}

