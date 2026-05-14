package com.substring.authapp.security;

import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.provider.GithubService;
import com.substring.authapp.services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuth2SuccessHandlerTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private GithubService githubService;

    @Mock
    private OAuth2AuthorizedClientService authorizedClientService;

    @Mock
    private AuthService authService;

    @InjectMocks
    private OAuth2SuccessHandler oAuth2SuccessHandler;

    private HttpServletRequest request;
    private HttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        ReflectionTestUtils.setField(oAuth2SuccessHandler, "frontendRedirectUrl", "http://localhost:3000/oauth2/redirect/");
    }

    @Test
    void onAuthenticationSuccess_WithNewGitHubUser_ShouldProvisionAndRedirect() throws Exception {
        // Setup mocks for GitHub user info
        OAuth2User oAuth2User = mock(OAuth2User.class);
        when(oAuth2User.getAttribute("email")).thenReturn("newuser@github.com");
        when(oAuth2User.getAttribute("name")).thenReturn("New User");
        when(oAuth2User.getAttribute("avatar_url")).thenReturn("http://image.url");

        OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(authentication.getAuthorizedClientRegistrationId()).thenReturn("github");

        // Mock DB behavior
        when(userRepository.findByEmail("newuser@github.com")).thenReturn(Optional.empty());
        Role userRole = new Role(UUID.randomUUID(), UserRole.ROLE_USER);
        when(roleRepository.findByName(UserRole.ROLE_USER)).thenReturn(Optional.of(userRole));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // Action
        oAuth2SuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(userRepository).save(argThat(user -> 
            user.getEmail().equals("newuser@github.com") &&
            user.getProvider() == Provider.GITHUB &&
            user.getRoles().contains(userRole)
        ));
        verify(authService).generateOAuth2AuthenticatedResponse(any(User.class), eq(response));
        verify(response).sendRedirect(contains("/oauth2/redirect/"));
    }

    @Test
    void onAuthenticationSuccess_WithExistingUser_ShouldNotProvisionNewUser() throws Exception {
        // Setup mocks for Google user info
        OAuth2User oAuth2User = mock(OAuth2User.class);
        when(oAuth2User.getAttribute("email")).thenReturn("existing@google.com");
        when(oAuth2User.getAttribute("name")).thenReturn("Existing User");
        when(oAuth2User.getAttribute("picture")).thenReturn("http://image.url");

        OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(authentication.getAuthorizedClientRegistrationId()).thenReturn("google");

        // Mock DB behavior
        User existingUser = User.builder().email("existing@google.com").build();
        when(userRepository.findByEmail("existing@google.com")).thenReturn(Optional.of(existingUser));

        // Action
        oAuth2SuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(userRepository, never()).save(any(User.class));
        verify(authService).generateOAuth2AuthenticatedResponse(eq(existingUser), eq(response));
        verify(response).sendRedirect(anyString());
    }

    @Test
    void onAuthenticationSuccess_WhenGitHubEmailIsPrivate_ShouldCallGithubService() throws Exception {
        // Setup mocks for GitHub user info with null email
        OAuth2User oAuth2User = mock(OAuth2User.class);
        lenient().when(oAuth2User.getAttribute("email")).thenReturn(null);
        lenient().when(oAuth2User.getAttribute("name")).thenReturn(null);
        lenient().when(oAuth2User.getAttribute("login")).thenReturn("ghuser");
        lenient().when(oAuth2User.getAttribute("avatar_url")).thenReturn("http://image.url");

        OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
        lenient().when(authentication.getPrincipal()).thenReturn(oAuth2User);
        lenient().when(authentication.getAuthorizedClientRegistrationId()).thenReturn("github");
        lenient().when(authentication.getName()).thenReturn("ghuser");

        // Mock back-channel call
        when(githubService.getEmailFromGithub(any())).thenReturn("private@github.com");
        
        // Mock DB behavior
        User user = User.builder().email("private@github.com").build();
        when(userRepository.findByEmail("private@github.com")).thenReturn(Optional.of(user));

        // Action
        oAuth2SuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(githubService).getEmailFromGithub(any());
        verify(authService).generateOAuth2AuthenticatedResponse(eq(user), eq(response));
    }
}
