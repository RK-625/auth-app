package com.substring.authapp.security;

import com.substring.authapp.dtos.TokenResponse;
import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;
import com.substring.authapp.repositories.RefreshTokenRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.provider.GithubService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Strategy class to handle post-authentication logic for OAuth2 providers (Google, GitHub).
 * Automatically handles user provisioning and token issuance after a successful social login.
 */
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;
    private final GithubService githubService;
    private final OAuth2AuthorizedClientService authorizedClientService;

    public OAuth2SuccessHandler(UserRepository userRepository,
                                JwtService jwtService,
                                RefreshTokenRepository refreshTokenRepository,
                                CookieService cookieService,
                                ModelMapper modelMapper,
                                GithubService githubService,
                                OAuth2AuthorizedClientService authorizedClientService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.cookieService = cookieService;
        this.modelMapper = modelMapper;
        this.githubService = githubService;
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                        HttpServletResponse response, 
                                        Authentication authentication) throws IOException, ServletException {
        
        logger.info("Social authentication successful for principal: {}", authentication.getName());

        Map<String, Object> attributes = fetchAttributes(authentication);
        String email = (String) attributes.get("email");
        Provider provider = (Provider) attributes.get("provider");

        // Sync user with database (provisioning)
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = User.builder()
                    .email(email)
                    .name((String) attributes.get("name"))
                    .image((String) attributes.get("image"))
                    .enabled(true)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .provider(provider)
                    .build();
            return userRepository.save(newUser);
        });

        // Generate and persist refresh token
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenJti = UUID.randomUUID().toString();
        
        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(refreshTokenJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefereshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenOb);
        
        String refreshToken = jwtService.generateRefereshToken(user, refreshTokenJti);

        // Security headers and cookies
        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getAccessTtlSeconds());
        cookieService.addNoStoreHeadersToResponse(response);

        // Prepare token response
        TokenResponse tokenResponse = TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTtlSeconds(), "Bearer", modelMapper.map(user, UserDto.class));
        
        // Final redirection logic could be added here
        logger.info("OAuth2 flow complete for user: {}", email);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write("{\"status\": \"success\", \"message\": \"Authentication successful\"}");
    }

    /**
     * Extracts and normalizes user attributes across different OAuth2 providers.
     */
    private Map<String, Object> fetchAttributes(Authentication authentication) {
        Map<String, Object> res = new HashMap<>();
        OAuth2User oAuthUser = (OAuth2User) authentication.getPrincipal();
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        
        String registrationId = token.getAuthorizedClientRegistrationId();
        Provider provider = switch (registrationId) {
            case "google" -> Provider.GOOGLE;
            case "github" -> Provider.GITHUB;
            case "facebook" -> Provider.FACEBOOK;
            default -> Provider.LOCAL;
        };

        res.put("provider", provider);
        res.put("name", oAuthUser.getAttribute("name"));
        
        String image = provider == Provider.GOOGLE ? oAuthUser.getAttribute("picture")
                     : provider == Provider.GITHUB ? oAuthUser.getAttribute("avatar_url")
                     : "";
        res.put("image", image);

        // Special handling for GitHub which might hide email addresses
        String email = oAuthUser.getAttribute("email");
        if (email == null && provider == Provider.GITHUB) {
            email = githubService.getEmailFromGithub(
                authorizedClientService.loadAuthorizedClient(registrationId, token.getName())
            );
        }
        res.put("email", email);
        
        return res;
    }
}
