package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.auth.*;
import com.substring.authapp.dtos.user.AuthUserResponse;
import com.substring.authapp.entities.*;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.*;
import com.substring.authapp.security.CookieService;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.EmailService;
import com.substring.authapp.services.UserService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
    @Mock private MeterRegistry meterRegistry;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "initialTtl", 300L);
        ReflectionTestUtils.setField(authService, "gracePeriodTtl", 60L);
        
        // Mock MeterRegistry behavior
        Counter mockCounter = mock(Counter.class);
        lenient().when(meterRegistry.counter(anyString())).thenReturn(mockCounter);
    }

    // ===================================================================================
    // STEP 1: Signup Handshake Tests
    // ===================================================================================

    @Test
    void loginRequest_ShouldGenerateTokensAndCookies() {
        // Setup
        User user = new User();
        user.setId(UUID.randomUUID());
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(user);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(jwtService.generateAccessToken(user)).thenReturn("access-token");
        when(jwtService.getRefreshTtlSeconds()).thenReturn(3600L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(i -> i.getArgument(0));
        when(jwtService.generateRefreshToken(eq(user), anyString())).thenReturn("refresh-token");

        // Action
        TokenResponse result = authService.loginRequest(authentication, response);

        // Assert
        assertThat(result).isNotNull();
        verify(cookieService).attachRefreshCookie(eq(response), eq("refresh-token"), anyInt());
        verify(meterRegistry.counter("auth.login.success")).increment();
    }

    @Test
    void refreshTokenRequest_ShouldRotateTokens() {
        // Setup
        String oldTokenStr = "old-refresh-token";
        RefreshTokenRequest body = new RefreshTokenRequest(oldTokenStr);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        // Mock extraction
        lenient().when(cookieService.getRefreshTokenCookieName()).thenReturn("refreshToken");
        when(request.getCookies()).thenReturn(null);
        when(jwtService.isRefreshToken(oldTokenStr)).thenReturn(true);

        // Mock validation
        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        io.jsonwebtoken.Jws jws = mock(io.jsonwebtoken.Jws.class);
        when(jwtService.parse(oldTokenStr)).thenReturn(jws);
        when(jws.getPayload()).thenReturn(claims);
        when(claims.getId()).thenReturn("jti-123");
        UUID userId = UUID.randomUUID();
        when(claims.getSubject()).thenReturn(userId.toString());

        User user = new User();
        user.setId(userId);
        RefreshToken refreshTokenOb = RefreshToken.create(user, "jti-123", 3600L);
        when(refreshTokenRepository.findByJti("jti-123")).thenReturn(Optional.of(refreshTokenOb));

        // Mock rotation
        when(jwtService.getRefreshTtlSeconds()).thenReturn(3600L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(i -> i.getArgument(0));
        when(jwtService.generateAccessToken(user)).thenReturn("new-access");
        when(jwtService.generateRefreshToken(eq(user), anyString())).thenReturn("new-refresh");

        // Action
        TokenResponse result = authService.refreshTokenRequest(body, response, request);

        // Assert
        assertThat(result).isNotNull();
        assertThat(refreshTokenOb.isRevoked()).isTrue();
        verify(cookieService).attachRefreshCookie(eq(response), eq("new-refresh"), anyInt());
    }

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
    void signUpRequest_ShouldUpdateExistingHandshake_WhenSignupAlreadyInProgress() {
        // Setup
        String email = "test@example.com";
        SignUpInitiateRequest request = new SignUpInitiateRequest(email);
        SignUpObject existing = new SignUpObject(email, "old-otp", UUID.randomUUID(), 300L);
        existing.setLastSentAt(Instant.now().minusSeconds(120)); // Bypass cooldown

        doNothing().when(userHelper).validateSignUpEmail(email);
        when(signUpObjectRepository.findByEmail(email)).thenReturn(Optional.of(existing));
        when(userHelper.generateUniqueHandshakeKeys(any())).thenReturn(Pair.of("new-otp", UUID.randomUUID()));

        try (MockedStatic<TransactionSynchronizationManager> mockedStatic = mockStatic(TransactionSynchronizationManager.class)) {
            mockedStatic.when(TransactionSynchronizationManager::isSynchronizationActive).thenReturn(true);

            // Action
            authService.signUpRequest(request);

            // Assert
            verify(signUpObjectRepository).save(existing);
            assertThat(existing.getOtp()).isEqualTo("new-otp");

            // Verify and trigger email dispatch callback
            ArgumentCaptor<TransactionSynchronization> captor = ArgumentCaptor.forClass(TransactionSynchronization.class);
            mockedStatic.verify(() -> TransactionSynchronizationManager.registerSynchronization(captor.capture()));
            captor.getValue().afterCommit();
            verify(emailService).sendSignUpOtp(eq(email), eq("new-otp"));
        }
    }

    @Test
    void signUpRequest_WhenInCooldown_ShouldThrowBadCredentialsException() {
        // Setup
        String email = "test@example.com";
        SignUpInitiateRequest request = new SignUpInitiateRequest(email);
        SignUpObject existing = new SignUpObject(email, "old-otp", UUID.randomUUID(), 300L);
        existing.setLastSentAt(Instant.now().minusSeconds(30)); // IN COOLDOWN (less than 60s)

        doNothing().when(userHelper).validateSignUpEmail(email);
        when(signUpObjectRepository.findByEmail(email)).thenReturn(Optional.of(existing));
        when(messageHelper.getMessage("auth.otp.cooldown")).thenReturn("Wait please");

        // Action & Assert
        assertThatThrownBy(() -> authService.signUpRequest(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Wait please");
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
        assertThat(returnedToken).isEqualTo(token.toString());
        assertThat(signUpObject.isUsed()).isTrue();
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

    when(signUpObjectRepository.findByEmailAndExpiresAtGreaterThanAndSignUpToken(
            eq(email), any(Instant.class), eq(UUID.fromString(token))))
            .thenReturn(Optional.of(signUpObject));

    // Action
    authService.verifySignUpToken(email, token, password);

    // Assert
    verify(userHelper).buildAndSaveUser(email, password, null, Provider.LOCAL, UserRole.ROLE_USER);
    verify(signUpObjectRepository).delete(signUpObject);
}

@Test
void verifySignUpToken_WithUnverifiedOtp_ShouldThrowException() {
    // Setup
    String email = "test@example.com";        String otp = "123456";
        String token = UUID.randomUUID().toString();
        
        SignUpObject signUpObject = new SignUpObject(email, otp, UUID.fromString(token), 300L);
        signUpObject.setUsed(false); // NOT VERIFIED

        when(signUpObjectRepository.findByEmailAndExpiresAtGreaterThanAndSignUpToken(
                eq(email), any(Instant.class), eq(UUID.fromString(token))))
                .thenReturn(Optional.of(signUpObject));
        when(messageHelper.getMessage("signup.validation.failure")).thenReturn("Validation failed");

        // Action & Assert
        assertThatThrownBy(() -> authService.verifySignUpToken(email, token, "pass"))
                .isInstanceOf(BadCredentialsException.class);
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
        assertThat(oldToken.isRevoked()).isTrue();
        assertThat(oldToken.getReplacedByToken()).isNotNull();
        assertThat(oldToken.getReplacedByToken()).isEqualTo(newToken.getJti());
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
        assertThat(refreshToken.isRevoked()).isTrue();
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

    // ===================================================================================
    // STEP 4: Password Reset Handshake Tests
    // ===================================================================================

    @Test
    void initiatePasswordReset_ShouldCreateResetObjectAndSendEmail() {
        // Setup
        String email = "test@example.com";
        User user = new User();
        user.setEmail(email);

        when(userHelper.validateAndGetUserForAuth(email)).thenReturn(user);
        when(resetPasswordObjectRepository.findByUserAndExpiresAtGreaterThan(eq(user), any(Instant.class)))
                .thenReturn(Optional.empty());
        when(userHelper.generateUniqueHandshakeKeys(any())).thenReturn(Pair.of("123456", UUID.randomUUID()));

        try (MockedStatic<TransactionSynchronizationManager> mockedStatic = mockStatic(TransactionSynchronizationManager.class)) {
            mockedStatic.when(TransactionSynchronizationManager::isSynchronizationActive).thenReturn(true);
            
            // Action
            authService.initiatePasswordReset(email);

            // Assert
            verify(resetPasswordObjectRepository).deleteAllByUser(user);
            verify(resetPasswordObjectRepository).save(any(ResetPasswordObject.class));

            ArgumentCaptor<TransactionSynchronization> captor = ArgumentCaptor.forClass(TransactionSynchronization.class);
            mockedStatic.verify(() -> TransactionSynchronizationManager.registerSynchronization(captor.capture()));
            
            captor.getValue().afterCommit();
            verify(emailService).sendPassWordResetOtp(eq(email), eq("123456"));
        }
    }

    @Test
    void verifyPasswordResetOtp_ShouldReturnTokenAndMarkAsUsed() {
        // Setup
        String email = "test@example.com";
        String otp = "123456";
        User user = new User();
        UUID resetToken = UUID.randomUUID();
        ResetPasswordObject resetObject = new ResetPasswordObject(user, otp, resetToken, 300L);
        resetObject.setUsed(false);

        when(userHelper.validateAndGetUserForAuth(email)).thenReturn(user);
        when(resetPasswordObjectRepository.findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(eq(user), eq(otp), any(Instant.class)))
                .thenReturn(Optional.of(resetObject));

        // Action
        String returnedToken = authService.verifyPasswordResetOtp(email, otp);

        // Assert
        assertThat(returnedToken).isEqualTo(resetToken.toString());
        assertThat(resetObject.isUsed()).isTrue();
        verify(resetPasswordObjectRepository).save(resetObject);
    }

    @Test
    void resetPassword_WithValidToken_ShouldUpdatePasswordAndCleanup() {
        // Setup
        String email = "test@example.com";
        String otp = "123456";
        String resetToken = UUID.randomUUID().toString();
        String newPassword = "newSecurePassword";
        
        User user = new User();
        user.setEmail(email);

        when(userHelper.validateAndGetUserForAuth(email)).thenReturn(user);
        when(resetPasswordObjectRepository.findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(
                eq(user), any(Instant.class), eq(otp), eq(UUID.fromString(resetToken))))
                .thenReturn(Optional.of(new ResetPasswordObject()));
        when(passwordEncoder.encode(newPassword)).thenReturn("encodedPassword");

        // Action
        authService.resetPassword(email, otp, resetToken, newPassword);

        // Assert
        assertThat(user.getPassword()).isEqualTo("encodedPassword");
        assertThat(user.getTokenVersion()).isEqualTo(1);
        verify(refreshTokenRepository).revokeAllByUser(user);
        verify(userRepository).save(user);
        verify(resetPasswordObjectRepository).deleteAllByUser(user);
    }

    @Test
    void resetPassword_WithInvalidToken_ShouldThrowException() {
        // Setup
        String email = "test@example.com";
        String otp = "wrong-otp";
        String resetToken = UUID.randomUUID().toString();
        
        User user = new User();
        when(userHelper.validateAndGetUserForAuth(email)).thenReturn(user);
        when(resetPasswordObjectRepository.findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(
                eq(user), any(Instant.class), eq(otp), eq(UUID.fromString(resetToken))))
                .thenReturn(Optional.empty());
        when(messageHelper.getMessage("auth.forget.otp_invalid")).thenReturn("Invalid token");

        // Action & Assert
        assertThatThrownBy(() -> authService.resetPassword(email, otp, resetToken, "password"))
                .isInstanceOf(BadCredentialsException.class);
    }

    // ===================================================================================
    // STEP 5: Kill-Switch Test
    // ===================================================================================

    @Test
    void getValidatedRefreshToken_WhenTokenRevoked_ShouldTriggerKillSwitch() {
        // Setup
        String tokenStr = "stolen-jwt";
        String jti = "compromised-jti";
        UUID userId = UUID.randomUUID();
        User user = new User();
        user.setId(userId);

        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        io.jsonwebtoken.Jws jws = mock(io.jsonwebtoken.Jws.class);
        lenient().when(jwtService.parse(tokenStr)).thenReturn(jws);
        lenient().when(jws.getPayload()).thenReturn(claims);
        lenient().when(claims.getId()).thenReturn(jti);
        lenient().when(claims.getSubject()).thenReturn(userId.toString());

        RefreshToken compromisedToken = RefreshToken.create(user, jti, 3600L);
        compromisedToken.setRevoked(true); // Token is already revoked (stolen)

        when(refreshTokenRepository.findByJti(jti)).thenReturn(Optional.of(compromisedToken));
        when(messageHelper.getMessage(anyString())).thenReturn("Error message");

        // Action & Assert
        assertThatThrownBy(() -> authService.getValidatedRefreshToken(tokenStr))
                .isInstanceOf(BadCredentialsException.class);
        
        // Verify the Kill-Switch was triggered
        verify(refreshTokenRepository).revokeAllByUser(user);
    }

    @Test
    void getValidatedRefreshToken_WhenExpired_ShouldThrowException() {
        String tokenStr = "expired-jwt";
        String jti = "jti-123";
        UUID userId = UUID.randomUUID();
        User user = new User();
        user.setId(userId);

        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        io.jsonwebtoken.Jws jws = mock(io.jsonwebtoken.Jws.class);
        when(jwtService.parse(tokenStr)).thenReturn(jws);
        when(jws.getPayload()).thenReturn(claims);
        when(claims.getId()).thenReturn(jti);
        when(claims.getSubject()).thenReturn(userId.toString());

        RefreshToken expiredToken = RefreshToken.create(user, jti, -100L); // EXPIRED
        when(refreshTokenRepository.findByJti(jti)).thenReturn(Optional.of(expiredToken));
        when(messageHelper.getMessage("token.refresh.expired")).thenReturn("Expired");

        assertThatThrownBy(() -> authService.getValidatedRefreshToken(tokenStr))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Expired");
    }

    @Test
    void getValidatedRefreshToken_WhenNotFoundInDb_ShouldThrowException() {
        String tokenStr = "unknown-jwt";
        String jti = "jti-missing";

        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        io.jsonwebtoken.Jws jws = mock(io.jsonwebtoken.Jws.class);
        when(jwtService.parse(tokenStr)).thenReturn(jws);
        when(jws.getPayload()).thenReturn(claims);
        when(claims.getId()).thenReturn(jti);
        when(claims.getSubject()).thenReturn(UUID.randomUUID().toString());

        when(refreshTokenRepository.findByJti(jti)).thenReturn(Optional.empty());
        when(messageHelper.getMessage("token.refresh.not_found_db")).thenReturn("Not found");

        assertThatThrownBy(() -> authService.getValidatedRefreshToken(tokenStr))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Not found");
    }

    @Test
    void getValidatedRefreshToken_WhenUserMismatch_ShouldThrowException() {
        String tokenStr = "valid-jwt";
        String jti = "jti-123";
        UUID tokenUserId = UUID.randomUUID();
        UUID actualUserId = UUID.randomUUID(); // MISMATCH

        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        io.jsonwebtoken.Jws jws = mock(io.jsonwebtoken.Jws.class);
        when(jwtService.parse(tokenStr)).thenReturn(jws);
        when(jws.getPayload()).thenReturn(claims);
        when(claims.getId()).thenReturn(jti);
        when(claims.getSubject()).thenReturn(tokenUserId.toString());

        User actualUser = new User();
        actualUser.setId(actualUserId);
        RefreshToken tokenOb = RefreshToken.create(actualUser, jti, 3600L);
        
        when(refreshTokenRepository.findByJti(jti)).thenReturn(Optional.of(tokenOb));
        when(messageHelper.getMessage("token.refresh.user_mismatch")).thenReturn("Mismatch");

        assertThatThrownBy(() -> authService.getValidatedRefreshToken(tokenStr))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Mismatch");
    }

    @Test
    void processLogout_WhenTokenInvalid_ShouldStillClearCookies() {
        // Setup
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        RefreshTokenRequest body = new RefreshTokenRequest("invalid-token");

        // Mock extractRefreshToken to throw exception
        lenient().when(cookieService.getRefreshTokenCookieName()).thenReturn("refreshToken");
        when(request.getCookies()).thenReturn(null);
        when(jwtService.isRefreshToken("invalid-token")).thenReturn(false);
        when(messageHelper.getMessage("token.refresh.invalid")).thenReturn("Invalid");

        // Action
        authService.processLogout(body, request, response);

        // Assert
        verify(cookieService).clearRefreshCookie(response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
