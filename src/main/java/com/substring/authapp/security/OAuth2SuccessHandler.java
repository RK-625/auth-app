package com.substring.authapp.security;

import com.substring.authapp.entities.*;
import com.substring.authapp.helpers.TokenHelper;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.RefreshTokenRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.provider.GithubService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.HashSet;
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
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final GithubService githubService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenHelper tokenHelper;

    public OAuth2SuccessHandler(UserRepository userRepository,
                                RoleRepository roleRepository,
                                JwtService jwtService,
                                RefreshTokenRepository refreshTokenRepository,
                                GithubService githubService,
                                OAuth2AuthorizedClientService authorizedClientService,
                                TokenHelper tokenHelper) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.githubService = githubService;
        this.authorizedClientService = authorizedClientService;
        this.tokenHelper = tokenHelper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                        HttpServletResponse response, 
                                        Authentication authentication) throws IOException, ServletException {
        
        logger.info("Social authentication successful for principal: {}", authentication.getName());

        // 1. Normalize attributes from different providers (Google, GitHub, etc.)
        Map<String, Object> attributes = fetchAttributes(authentication);
        String email = (String) attributes.get("email");
        Provider provider = (Provider) attributes.get("provider");

        // 2. Synchronize social user with the local database (Auto-provisioning)
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            Role userRole = roleRepository.findByName(UserRole.ROLE_USER.name())
                    .orElseThrow(() -> new IllegalStateException("Default role ROLE_USER not found"));

            User newUser = User.builder()
                    .email(email)
                    .name((String) attributes.get("name"))
                    .image((String) attributes.get("image"))
                    .enabled(true)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .provider(provider)
                    .roles(new HashSet<>(java.util.List.of(userRole)))
                    .build();
            return userRepository.save(newUser);
        });

        // 3. Convert the OAuth2 session into a stateless JWT-based session
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenJti = UUID.randomUUID().toString();
        
        // 4. Persist a matching refresh token in the database for future revocation
        RefreshToken refreshTokenOb = RefreshToken.create(user, refreshTokenJti, jwtService.getRefreshTtlSeconds());
        refreshTokenRepository.save(refreshTokenOb);
        
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenJti);

        // 5. Attach tokens to the response (Secure HttpOnly cookies and headers)
        tokenHelper.generateAuthenticatedResponse(response, user, accessToken, refreshToken);

        // 6. Redirect the user back to the frontend application with the access token
        // Assumptions: Frontend is running on localhost:3000
        String targetUrl = "http://localhost:3000/oauth2/redirect?token=" + accessToken;
        logger.info("OAuth2 flow complete. Redirecting {} to: {}", email, targetUrl);
        response.sendRedirect(targetUrl);
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
