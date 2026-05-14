package com.substring.authapp.security;

import com.substring.authapp.entities.User;
import com.substring.authapp.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.impl.DefaultClaims;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_WithValidToken_PopulatesSecurityContext() throws Exception {
        String token = "valid.jwt.token";
        request.addHeader("Authorization", "Bearer " + token);
        UUID userId = UUID.randomUUID();

        User user = new User();
        user.setId(userId);
        user.setEnabled(true);

        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(userId.toString());
        
        @SuppressWarnings("unchecked")
        Jws<Claims> jws = mock(Jws.class);
        when(jws.getPayload()).thenReturn(claims);

        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.parse(token)).thenReturn(jws);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isEqualTo(user);
        verify(filterChain).doFilter(request, response);
    }
    
    @Test
    void doFilterInternal_WithoutBearerToken_ContinuesChainWithoutAuthentication() throws Exception {
        request.addHeader("Authorization", "Basic some-token");

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithExpiredToken_SetsErrorAttribute() throws Exception {
        String token = "expired.jwt.token";
        request.addHeader("Authorization", "Bearer " + token);

        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.parse(token)).thenThrow(new ExpiredJwtException(null, null, "Expired"));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(request.getAttribute("error")).isEqualTo("Token has expired");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithDisabledUser_ShouldNotPopulateContext() throws Exception {
        String token = "valid.token";
        request.addHeader("Authorization", "Bearer " + token);
        UUID userId = UUID.randomUUID();

        User user = new User();
        user.setId(userId);
        user.setEnabled(false); // DISABLED

        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(userId.toString());
        @SuppressWarnings("unchecked")
        Jws<Claims> jws = mock(Jws.class);
        when(jws.getPayload()).thenReturn(claims);

        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.parse(token)).thenReturn(jws);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithMalformedToken_ShouldSetErrorAttribute() throws Exception {
        String token = "malformed.token";
        request.addHeader("Authorization", "Bearer " + token);

        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.parse(token)).thenThrow(new RuntimeException("Malformed"));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(request.getAttribute("error")).isEqualTo("Token is not valid");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotFilter_ForAuthEndpoints_ShouldReturnTrue() {
        request.setRequestURI("/api/v1/auth/login");
        assertThat(jwtAuthenticationFilter.shouldNotFilter(request)).isTrue();
        
        request.setRequestURI("/api/v1/users");
        assertThat(jwtAuthenticationFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    void doFilterInternal_WithNullAuthorizationHeader_ShouldContinueChain() throws Exception {
        // No header added
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }
}
