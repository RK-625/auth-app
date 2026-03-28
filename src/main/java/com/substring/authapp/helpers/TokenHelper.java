package com.substring.authapp.helpers;

import com.substring.authapp.dtos.RefreshTokenRequest;
import com.substring.authapp.dtos.TokenResponse;
import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.User;
import com.substring.authapp.security.CookieService;
import com.substring.authapp.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

/**
 * Utility helper to standardize the generation of authentication responses
 * and extracting tokens from requests.
 */
@Component
@RequiredArgsConstructor
public class TokenHelper {

    private final JwtService jwtService;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;
    private final MessageHelper messageHelper;

    /**
     * Orchestrates the final response for a successful authentication event.
     * 
     * @param response      The HttpServletResponse to attach cookies/headers to.
     * @param user          The authenticated User entity.
     * @param accessToken   The generated JWT access token.
     * @param refreshToken  The generated JWT refresh token.
     * @return A standardized TokenResponse DTO for the response body.
     */
    public TokenResponse generateAuthenticatedResponse(
            HttpServletResponse response,
            User user,
            String accessToken,
            String refreshToken) {
        
        // 1. Attach the Refresh Token as a Secure HttpOnly Cookie
        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getAccessTtlSeconds());
        
        // 2. Add security headers to prevent token caching in the browser
        cookieService.addNoStoreHeadersToResponse(response);
        
        // 3. Map User entity to DTO for the response body
        UserDto userDto = modelMapper.map(user, UserDto.class);
        
        // 4. Construct and return the final TokenResponse body
        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getAccessTtlSeconds())
                .tokenType("Bearer")
                .user(userDto)
                .build();
    }

    /**
     * Extracts and performs basic validation on the refresh token from the request.
     */
    public String extractRefreshToken(RefreshTokenRequest body, HttpServletRequest request) {
        String refreshToken = readRefreshTokenRequest(body, request)
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("token.refresh.not_present")));

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException(messageHelper.getMessage("token.refresh.invalid"));
        }
        return refreshToken;
    }

    private Optional<String> readRefreshTokenRequest(RefreshTokenRequest body, HttpServletRequest request) {
        if (request.getCookies() != null) {
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(cookieService.getRefreshTokenCookieName()))
                    .map(Cookie::getValue)
                    .filter(token -> !token.isBlank())
                    .findFirst();
            if (fromCookie.isPresent()) return fromCookie;
        }
        
        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }
        return Optional.empty();
    }
}
