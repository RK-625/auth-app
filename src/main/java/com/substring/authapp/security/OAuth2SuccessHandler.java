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
 * <h1>OAuth2 Protocol Orchestrator & JIT Provisioning Engine</h1>
 *
 * <p>This component is the terminal point of the <b>OAuth2 Authorization Code Grant</b> flow. 
 * It manages the critical transition from an external identity (Google/GitHub) to an 
 * internal application session.</p>
 * 
 * <p><b>The Hidden Handshake (Managed by Spring Security):</b>
 * Before this handler is triggered, the following "Invisible" steps occur:
 * <ol>
 *   <li><b>Interception:</b> The user clicks a link to {@code /oauth2/authorization/{provider}}. This URL is not 
 *       a real controller; it is intercepted by the <b>{@code OAuth2AuthorizationRequestRedirectFilter}</b>.</li>
 *   <li><b>Request Resolution:</b> The filter uses the <b>{@link org.springframework.security.oauth2.client.registration.ClientRegistrationRepository}</b> 
 *       to look up the <b>{@code client-id}</b> and <b>{@code client-secret}</b> configured in your properties. 
 *       It then constructs the Redirect URL (the IdP's login page).</li>
 *   <li><b>Authorization:</b> User grants permission on the IdP site. The IdP redirects the browser back to 
 *       {@code /login/oauth2/code/{provider}} with a temporary <b>{@code code}</b>.</li>
 *   <li><b>Token Exchange:</b> The <b>{@code OAuth2LoginAuthenticationFilter}</b> catches this callback. It executes 
 *       a back-channel {@code POST} to the IdP's token endpoint, sending your <b>{@code client-id}</b>, 
 *       <b>{@code client-secret}</b>, and the user's <b>{@code code}</b> to swap them for a social <b>{@code access_token}</b>.</li>
 *   <li><b>Resource Fetch:</b> Spring uses that social token to fetch user attributes and triggers this success handler.</li>
 * </ol>
 * </p>
 *
 * <p><b>Configuration-Driven Attribute Fetching:</b>
 * User data availability is controlled by the scopes in {@code application.yaml}:
 * {@code spring.security.oauth2.client.registration.[provider].scope}.
 * For example, {@code scope: [user:email, read:user]} must be present to fetch private GitHub emails. 
 * Missing scopes will result in {@code null} attributes during processing.
 * </p>
 *
 * <p><b>Architecture Component Map (The Ecosystem):</b>
 * <ul>
 *   <li><b>{@link org.springframework.security.oauth2.client.registration.ClientRegistrationRepository}</b>: 
 *       The "Vault" containing IdP metadata (Client IDs, Secrets, and Auth/Token/UserInfo URLs).</li>
 *   <li><b>{@code OAuth2LoginAuthenticationFilter}</b>: 
 *       The "Interceptor" that catches the code from the IdP and triggers the back-channel token swap.</li>
 *   <li><b>{@link org.springframework.security.oauth2.client.userinfo.OAuth2UserService}</b>: 
 *       The "Fetcher" that uses the social access token to download user attributes from the IdP's {@code /userinfo} endpoint.</li>
 *   <li><b>{@link OAuth2AuthorizedClientService}</b>: 
 *       The "Registry" that stores the social tokens, allowing us to perform secondary API calls to the IdP.</li>
 *   <li><b>{@link JwtService}</b>: 
 *       The "Signer" that converts the verified social session into an internal, stateless JWT.</li>
 * </ul>
 * </p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Normalization:</b> Extracts cross-provider attributes into a unified internal map.
 * 2. <b>Just-In-Time (JIT) Provisioning:</b> Atomically synchronizes the social identity with the {@link UserRepository}.
 * 3. <b>Credential Transition:</b> Swaps the stateful social session for a stateless internal JWT Access Token.
 * 4. <b>Audit Logging:</b> Records the login event and establishes a database-backed Refresh Token (The Kill-Switch).
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * - <b>{@link GithubService}</b>: Orchestrates secondary API calls to the IdP (Identity Provider) when standard 
 *   scopes are insufficient for identity resolution.
 * - <b>{@link OAuth2AuthorizedClientService}</b>: Provides the social access token required by the {@code GithubService}.
 * - <b>{@link JwtService}</b>: Converts the verified social identity into a signed, internal application session.
 * </p>
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

    /**
     * Executes the final security handshake after a successful OAuth2 provider login.
     *
     * <p><b>Implementation Workflow (The JIT Provisioning Cycle):</b>
     * 1. Extracts social attributes (Id, Email, Name) using {@link #fetchAttributes(Authentication)}.
     * 2. Performs an <b>Upsert</b> operation via {@link UserRepository}:
     *    - If the email exists, the local user profile is linked to the social provider.
     *    - If not, a new {@link User} is created on-the-fly (JIT) with {@code ROLE_USER}.
     * 3. Converts the provider-specific session into a local stateless session:
     *    - Generates a cryptographically signed Access JWT via {@link JwtService}.
     *    - Persists a new {@link RefreshToken} entity to the {@link RefreshTokenRepository} (The "Kill-Switch").
     * 4. Delegates response decoration (Cookies/Headers) to the {@link TokenHelper}.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * This method is the terminal point of the {@code OAuth2LoginAuthenticationFilter}. It acts as a 
     * <b>Service Orchestrator</b>, coordinating between JPA repositories for persistence, 
     * the JWT engine for security tokens, and the {@link GithubService} for extended attribute 
     * fetching when standard OAuth2 scopes (like {@code user:email}) are insufficient.</p>
     *
     * @param request The HttpServletRequest being processed.
     * @param response The HttpServletResponse to write to.
     * @param authentication The {@link Authentication} object representing the social identity.
     * @throws IOException If an input or output exception occurs during redirection.
     * @throws ServletException If the request for the success handler could not be handled.
     */
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
     * <h3>Provider Normalization Engine</h3>
     * <p>
     * Extracts user data from provider-specific attribute maps into a consistent internal format.
     * </p>
     *
     * <p><b>The {@link Authentication} Object (Anatomy of the Payload):</b>
     * When Spring Security triggers this handler, the generic {@code Authentication} object actually 
     * holds a massive, complex payload constructed during the OAuth2 handshake. We perform two 
     * critical <b>Type-Casts</b> to unlock this data:
     * <ul>
     *   <li><b>{@link OAuth2User} (The Principal):</b> Cast from {@code authentication.getPrincipal()}. 
     *       This represents the <i>Social Persona</i>. It contains the raw JSON attributes returned by 
     *       the Identity Provider's {@code /userinfo} endpoint (e.g., name, avatar_url).</li>
     *   <li><b>{@link OAuth2AuthenticationToken} (The Context):</b> Cast directly from {@code authentication}. 
     *       This represents the <i>Protocol State</i>. It holds metadata about the handshake, specifically 
     *       the {@code registrationId} ("github", "google") and the unique {@code getName()} of the user.</li>
     * </ul>
     * </p>
     *
     * <p><b>GitHub Special Case (Why we need Authorized Clients):</b>
     * GitHub often hides user emails by default. If the email is missing, we must trigger a secondary 
     * API call via {@link GithubService}. To make an authenticated call to GitHub's API on the user's behalf, 
     * the service needs a valid Social Access Token. 
     * <br><br>We fetch this token by passing two keys to the {@link OAuth2AuthorizedClientService}:
     * <ul>
     *   <li><b>{@code registrationId}</b>: Tells the service which provider vault to look in ("github").</li>
     *   <li><b>{@code token.getName()}</b>: The unique social ID of the user (The Principal Name) used as the lookup key.</li>
     * </ul>
     * The resulting {@code OAuth2AuthorizedClient} contains the raw {@code access_token} needed by the {@code GithubService} 
     * to authorize the HTTP GET request to {@code https://api.github.com/user/emails}.
     * </p>
     * 
     * @param authentication The current authentication token containing the Principal and IdP metadata.
     * @return A normalized map containing {@code email}, {@code name}, {@code image}, and {@code provider}.
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
