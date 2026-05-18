package com.substring.authapp.security;

import com.substring.authapp.entities.*;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.provider.GithubService;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.utils.PrivacyHelper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
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
import java.util.List;
import java.util.Map;

/**
 * <h1>OAuth2 Protocol Orchestrator & JIT Provisioning Engine</h1>
 *
 * <p>This component is the terminal point of the <b>OAuth2 Authorization Code Grant</b> flow. 
 * It manages the critical transition from an external identity (Google/GitHub) to an 
 * internal application session.</p>
 * 
 * <p><b>JIT (Just-In-Time) Provisioning & Profile Sync:</b>
 * This handler implements the <b>JIT Provisioning</b> pattern, which eliminates the 
 * need for a traditional "Social Sign-Up" page. When a user authenticates via a 
 * provider, the system automatically synchronizes the external profile with the 
 * local {@link User} entity:
 * <ul>
 *   <li><b>Profile Matching:</b> Uses the verified email address as the primary 
 *       uniqueness constraint.</li>
 *   <li><b>Dynamic Creation:</b> If no local user exists with that email, a new 
 *       account is created on-the-fly, initialized with the social provider's 
 *       metadata (name, avatar URL).</li>
 *   <li><b>Attribute Synchronization:</b> On every successful login, the system 
 *       refreshes the local {@code name} and {@code image} fields to ensure they 
 *       stay in sync with the social profile, maintaining a fresh user experience.</li>
 * </ul>
 * </p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Normalization:</b> Extracts cross-provider attributes into a unified internal map.
 * 2. <b>JIT Provisioning:</b> Atomically synchronizes the social identity with the {@link UserRepository}.
 * 3. <b>Credential Transition:</b> Swaps the stateful social session for a stateless internal JWT Access Token.
 * 4. <b>Handshake Finalization:</b> Delegates session generation and cookie injection to {@link AuthService}.
 * </p>
 * 
 * @author Gemini CLI
 */
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final GithubService githubService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final AuthService authService;

    @Value("${app.security.oauth2.redirect-url}")
    private String frontendRedirectUrl;

    // ===================================================================================
    // SECTION 2: Constructor (Dependency Injection)
    // ===================================================================================

    public OAuth2SuccessHandler(UserRepository userRepository,
                                RoleRepository roleRepository,
                                GithubService githubService,
                                OAuth2AuthorizedClientService authorizedClientService,
                                @Lazy AuthService authService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.githubService = githubService;
        this.authorizedClientService = authorizedClientService;
        this.authService = authService;
    }

    // ===================================================================================
    // SECTION 3: Success Handler Entry Point (The "Switchboard")
    // ===================================================================================

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                         HttpServletResponse response,
                                         Authentication authentication) throws IOException, ServletException {

        logger.info("Social authentication successful for principal: {}", authentication.getName());

        // 1. Normalize attributes
        Map<String, Object> attributes = fetchAttributes(authentication);
        String email = (String) attributes.get("email");
        Provider provider = (Provider) attributes.get("provider");

        // 2. Synchronize social user (JIT Provisioning & Attribute Sync)
        User user = userRepository.findByEmail(email).map(existingUser -> {
            // Attribute Synchronization: Update profile if it changed
            existingUser.setName((String) attributes.get("name"));
            existingUser.setImage((String) attributes.get("image"));
            existingUser.setUpdatedAt(Instant.now());
            return userRepository.save(existingUser);
        }).orElseGet(() -> {
            Role userRole = roleRepository.findByName(UserRole.ROLE_USER)
                    .orElseThrow(() -> new IllegalStateException("Default role ROLE_USER not found"));

            User newUser = User.builder()
                    .email(email)
                    .name((String) attributes.get("name"))
                    .image((String) attributes.get("image"))
                    .enabled(true)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .provider(provider)
                    .roles(new HashSet<>(List.of(userRole)))
                    .build();
            return userRepository.save(newUser);
        });

        // 3. Convert OAuth2 session into stateless JWT and stateful refresh token
        String accessToken = authService.generateOAuth2AuthenticatedResponse(user, response);

        // 4. Redirect back to frontend with the Access Token
        String targetUrl = frontendRedirectUrl + "?token=" + accessToken;
        logger.info("OAuth2 flow complete. Redirecting {} to: {}", PrivacyHelper.maskEmail(email), frontendRedirectUrl);
        response.sendRedirect(targetUrl);
    }

    // ===================================================================================
    // SECTION 4: Attribute Normalization Engine (Internal)
    // ===================================================================================

    /**
     * <h3>Provider Normalization Engine</h3>
     */
    private Map<String, Object> fetchAttributes(Authentication authentication) {
        Map<String, Object> res = new HashMap<>();
        OAuth2User oAuthUser = (OAuth2User) authentication.getPrincipal();
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;

        String registrationId = token.getAuthorizedClientRegistrationId();

        if ("github".equalsIgnoreCase(registrationId)) {
            res.put("provider", Provider.GITHUB);
            String email = oAuthUser.getAttribute("email");
            if (email == null) {
                // Secondary back-channel call to GitHub for private emails
                email = githubService.getEmailFromGithub(authorizedClientService.loadAuthorizedClient(registrationId, token.getName()));
            }
            res.put("email", email);
            res.put("name", oAuthUser.getAttribute("name") != null ? oAuthUser.getAttribute("name") : oAuthUser.getAttribute("login"));
            res.put("image", oAuthUser.getAttribute("avatar_url"));
        } else if ("google".equalsIgnoreCase(registrationId)) {
            res.put("provider", Provider.GOOGLE);
            res.put("email", oAuthUser.getAttribute("email"));
            res.put("name", oAuthUser.getAttribute("name"));
            res.put("image", oAuthUser.getAttribute("picture"));
        }
        return res;
    }
}