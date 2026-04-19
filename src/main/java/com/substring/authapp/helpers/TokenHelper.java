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
 * <h1>Authentication Response Orchestrator</h1>
 *
 * <p>This helper component centralizes the logic for constructing standardized authentication responses
 * and extracting security tokens from incoming requests. It acts as a bridge between the service layer
 * and the HTTP transport layer.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Response Assembly:</b> Combines user data, access tokens, and refresh tokens into a unified DTO.
 * 2. <b>Security Injection:</b> Attaches sensitive tokens to secure HTTP-only cookies.
 * 3. <b>Extraction:</b> Implements a priority-based strategy for retrieving tokens from cookies or request bodies.</p>
 *
 * <p><b>Behind the Scenes:</b>
 * Coordinates with {@link CookieService} to manipulate the {@link HttpServletResponse} and uses
 * {@link JwtService} to validate token types during extraction. It leverages {@link ModelMapper}
 * to ensure that internal {@link User} entities are safely projected into {@link UserDto}s.</p>
 *
 * <p><b>Design Rationale:</b>
 * Centralizing this logic ensures that every authentication event (login, refresh, social login)
 * results in a consistent response structure, simplifying frontend integration and enhancing security
 * by enforcing best practices like {@code HttpOnly} cookies across the board.</p>
 *
 * @author Gemini CLI
 * @see CookieService
 * @see JwtService
 */
@Component
@RequiredArgsConstructor
public class TokenHelper {

    private final JwtService jwtService;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;
    private final MessageHelper messageHelper;

    /**
     * Generates a complete authentication response including body payload and security cookies.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Cookie Attachment:</b> Invokes {@link CookieService} to set the Refresh Token as a secure cookie.
     * 2. <b>Header Configuration:</b> Adds 'No-Cache' headers to prevent token leakage in browser history.
     * 3. <b>DTO Projection:</b> Maps the {@link User} entity to a {@link UserDto} to hide sensitive fields.
     * 4. <b>Response Construction:</b> Builds the final {@link TokenResponse} with the access token and expiry details.</p>
     *
     * <p><b>Behind the Scenes:</b>
     * The refresh token is set with an expiry matching its internal TTL, ensuring the cookie is cleared
     * by the browser when the token is no longer valid. The access token is returned in the JSON body
     * to be used in the {@code Authorization: Bearer} header by the client.</p>
     *
     * <p><b>Design Rationale:</b>
     * Splitting the tokens (Refresh in Cookie, Access in Body) provides a balance between security
     * (Refresh Token is less accessible to XSS) and usability (Access Token is easily managed by the client).</p>
     *
     * @param response The HttpServletResponse to modify.
     * @param user The authenticated user.
     * @param accessToken The signed access JWT.
     * @param refreshToken The signed refresh JWT.
     * @return A {@link TokenResponse} containing the access token and user metadata.
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
     * Extracts a refresh token from the request using a hierarchical strategy.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Cookie Search:</b> Checks for the presence of the refresh token cookie.
     * 2. <b>Body Fallback:</b> If no cookie is found, attempts to read from the JSON request body.
     * 3. <b>Validation:</b> Verifies the token's type using {@link JwtService}.
     * 4. <b>Error Handling:</b> Throws a {@link BadCredentialsException} if the token is missing or invalid.</p>
     *
     * <p><b>Behind the Scenes:</b>
     * The {@link JwtService#isRefreshToken(String)} call inspects the token's claims (typically a 'typ' claim)
     * to prevent 'token type confusion' attacks where an access token is used as a refresh token.</p>
     *
     * <p><b>Design Rationale:</b>
     * Prioritizing cookies ensures that web-based clients remain secure, while the body fallback
     * provides compatibility with mobile apps and API testing tools that might not support cookies easily.</p>
     *
     * @param body The optional {@link RefreshTokenRequest} body.
     * @param request The {@link HttpServletRequest} containing cookies.
     * @return The validated refresh token string.
     * @throws BadCredentialsException If the token is missing or is not a refresh token.
     */
    public String extractRefreshToken(RefreshTokenRequest body, HttpServletRequest request) {
        String refreshToken = readRefreshTokenRequest(body, request)
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("token.refresh.not_present")));

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException(messageHelper.getMessage("token.refresh.invalid"));
        }
        return refreshToken;
    }

    /**
     * Internal extraction strategy: Checks Cookies first, then falls back to Request Body.
     */
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
