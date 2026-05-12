package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.auth.RefreshTokenRequest;
import com.substring.authapp.dtos.auth.SignUpInitiateRequest;
import com.substring.authapp.entities.*;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.*;
import com.substring.authapp.security.CookieService;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.EmailService;
import com.substring.authapp.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.data.util.Pair;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock private UserService userService;
    @Mock private UserRepository userRepository;
    @Mock private UserHelper userHelper;
    @Mock private MessageHelper messageHelper;
    @Mock private RoleRepository roleRepository;
    @Mock private SignUpObjectRepository signUpObjectRepository;
    @Mock private ResetPasswordObjectRepository resetPasswordObjectRepository;
    @Mock private EmailService emailService;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private JwtService jwtService;
    @Mock private CookieService cookieService;
    @Mock private ModelMapper modelMapper;

    @InjectMocks
    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "initialTtl", 300L);
        ReflectionTestUtils.setField(authService, "gracePeriodTtl", 60L);
    }

    // ===================================================================================
    // STEP 1: Signup Handshake Tests
    // ===================================================================================

    @Test
    void signUpRequest_ShouldGenerateNewHandshakeAndDispatchEmail() {
        // Setup
        String email = "test@example.com";
        SignUpInitiateRequest request = new SignUpInitiateRequest(email);
        String dummyOtp = "123456";
        UUID dummyToken = UUID.randomUUID();

        doNothing().when(userHelper).validateSignUpEmail(email);
        when(signUpObjectRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(userHelper.generateUniqueHandshakeKeys(any())).thenReturn(Pair.of(dummyOtp, dummyToken));

        try (MockedStatic<TransactionSynchronizationManager> mockedStatic = mockStatic(TransactionSynchronizationManager.class)) {
            mockedStatic.when(TransactionSynchronizationManager::isSynchronizationActive).thenReturn(true);
            
            // Action
            authService.signUpRequest(request);

            // Assert
            verify(signUpObjectRepository).save(any(SignUpObject.class));
            
            ArgumentCaptor<TransactionSynchronization> captor = ArgumentCaptor.forClass(TransactionSynchronization.class);
            mockedStatic.verify(() -> TransactionSynchronizationManager.registerSynchronization(captor.capture()));
            
            // Manually trigger the synchronization callback
            captor.getValue().afterCommit();
            verify(emailService).sendSignUpOtp(eq(email), eq(dummyOtp));
        }
    }

    @Test
    void verifySignUpOtp_WithValidOtp_ShouldTransitionStateToUsed() {
        // Setup
        String email = "test@example.com";
        String otp = "123456";
        UUID token = UUID.randomUUID();
        SignUpObject signUpObject = new SignUpObject(email, otp, token, 300L);
        signUpObject.setUsed(false);

        doNothing().when(userHelper).validateSignUpEmail(email);
        when(signUpObjectRepository.findByEmailAndOtpAndExpiresAtGreaterThan(eq(email), eq(otp), any(Instant.class)))
                .thenReturn(Optional.of(signUpObject));

        // Action
        String returnedToken = authService.verifySignUpOtp(email, otp);

        // Assert
        assertEquals(token.toString(), returnedToken);
        assertTrue(signUpObject.isUsed());
        verify(signUpObjectRepository).save(signUpObject);
    }

    @Test
    void verifySignUpToken_WithValidAndUsedToken_ShouldProvisionUser() {
        // Setup
        String email = "test@example.com";
        String otp = "123456";
        String token = UUID.randomUUID().toString();
        String password = "password123";
        
        SignUpObject signUpObject = new SignUpObject(email, otp, UUID.fromString(token), 300L);
        signUpObject.setUsed(true);

        when(signUpObjectRepository.findByEmailAndOtpAndExpiresAtGreaterThanAndSignUpToken(
                eq(email), eq(otp), any(Instant.class), eq(UUID.fromString(token))))
                .thenReturn(Optional.of(signUpObject));

        // Action
        authService.verifySignUpToken(email, otp, token, password);

        // Assert
        verify(userHelper).buildAndSaveUser(email, password, null, Provider.LOCAL, UserRole.ROLE_USER);
        verify(signUpObjectRepository).delete(signUpObject);
    }

    @Test
    void verifySignUpToken_WithUnverifiedOtp_ShouldThrowException() {
        // Setup
        String email = "test@example.com";
        String otp = "123456";
        String token = UUID.randomUUID().toString();
        
        SignUpObject signUpObject = new SignUpObject(email, otp, UUID.fromString(token), 300L);
        signUpObject.setUsed(false); // NOT VERIFIED

        when(signUpObjectRepository.findByEmailAndOtpAndExpiresAtGreaterThanAndSignUpToken(
                eq(email), eq(otp), any(Instant.class), eq(UUID.fromString(token))))
                .thenReturn(Optional.of(signUpObject));
        when(messageHelper.getMessage("signup.validation.failure")).thenReturn("Validation failed");

        // Action & Assert
        assertThrows(BadCredentialsException.class, () -> 
            authService.verifySignUpToken(email, otp, token, "pass"));
    }

    // ===================================================================================
    // STEP 2: Session Lifecycle Tests
    // ===================================================================================

    @Test
    void rotateRefreshToken_ShouldRevokeOldTokenAndIssueNewOne() {
        // Setup
        User user = new User();
        user.setId(UUID.randomUUID());
        RefreshToken oldToken = RefreshToken.create(user, "old-jti", 3600L);
        
        when(jwtService.getRefreshTtlSeconds()).thenReturn(3600L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(i -> i.getArgument(0));

        // Action
        RefreshToken newToken = authService.rotateRefreshToken(oldToken);

        // Assert
        assertTrue(oldToken.isRevoked());
        assertNotNull(oldToken.getReplacedByToken());
        assertEquals(newToken.getJti(), oldToken.getReplacedByToken());
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }

    @Test
    void processLogout_ShouldRevokeTokenAndClearCookies() {
        // Setup
        String tokenStr = "dummy-jwt";
        RefreshTokenRequest body = new RefreshTokenRequest(tokenStr);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        
        // Mock token extraction
        lenient().when(cookieService.getRefreshTokenCookieName()).thenReturn("refreshToken");
        when(request.getCookies()).thenReturn(null); // Force body extraction
        when(jwtService.isRefreshToken(tokenStr)).thenReturn(true);
        
        // Mock getValidatedRefreshToken
        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        io.jsonwebtoken.Jws jws = mock(io.jsonwebtoken.Jws.class);
        lenient().when(jwtService.parse(tokenStr)).thenReturn(jws);
        lenient().when(jws.getPayload()).thenReturn(claims);
        lenient().when(claims.getId()).thenReturn("jti-123");
        
        UUID userId = UUID.randomUUID();
        lenient().when(claims.getSubject()).thenReturn(userId.toString());
        
        User user = new User();
        user.setId(userId);
        RefreshToken refreshToken = RefreshToken.create(user, "jti-123", 3600L);
        lenient().when(refreshTokenRepository.findByJti("jti-123")).thenReturn(Optional.of(refreshToken));

        // Action
        authService.processLogout(body, request, response);

        // Assert
        assertTrue(refreshToken.isRevoked());
        verify(refreshTokenRepository).save(refreshToken);
        verify(cookieService).clearRefreshCookie(response);
    }

    // ===================================================================================
    // STEP 3: OAuth2 JIT Provisioning
    // ===================================================================================

    @Test
    void generateOAuth2AuthenticatedResponse_ShouldCreateRefreshSessionAndCookies() {
        // Setup
        User user = new User();
        user.setId(UUID.randomUUID());
        HttpServletResponse response = mock(HttpServletResponse.class);
        
        when(jwtService.getRefreshTtlSeconds()).thenReturn(3600L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(i -> i.getArgument(0));
        when(jwtService.generateRefreshToken(eq(user), anyString())).thenReturn("new-refresh-token");

        // Action
        authService.generateOAuth2AuthenticatedResponse(user, response);

        // Assert
        verify(refreshTokenRepository).save(any(RefreshToken.class));
        verify(cookieService).attachRefreshCookie(eq(response), eq("new-refresh-token"), anyInt());
        verify(cookieService).addNoStoreHeadersToResponse(response);
    }
}
