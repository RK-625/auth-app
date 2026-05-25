package com.substring.authapp.helpers;

import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.util.Pair;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserHelper Unit Tests")
class UserHelperTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private MessageHelper messageHelper;

    @InjectMocks
    private UserHelper userHelper;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(userHelper, "minPasswordLength", 6);
        ReflectionTestUtils.setField(userHelper, "maxPasswordLength", 72);
    }

    @Test
    @DisplayName("Should generate valid 6-digit OTP and UUID")
    void generateSecureOtpAndToken_ShouldGenerateSixDigitOtpAndUUID() {
        Pair<String, UUID> result = UserHelper.generateSecureOtpAndToken();

        assertThat(result.getFirst()).hasSize(6);
        assertThat(Integer.parseInt(result.getFirst())).isBetween(100000, 999999);
        assertThat(result.getSecond()).isNotNull();
    }

    @Test
    @DisplayName("Should retry key generation on collision")
    void generateUniqueHandshakeKeys_ShouldRetryOnCollision() {
        // We create a predicate that fails once and then succeeds
        AtomicInteger counter = new AtomicInteger(0);
        Predicate<Pair<String, UUID>> collisionChecker = pair -> {
            if (counter.getAndIncrement() == 0) {
                return true; // Simulate collision on first try
            }
            return false; // Success on second try
        };

        Pair<String, UUID> result = userHelper.generateUniqueHandshakeKeys(collisionChecker);

        assertThat(result).isNotNull();
        assertThat(counter.get()).isEqualTo(2); // Should have been called twice
    }

    @Test
    @DisplayName("Should validate valid signup data without exception")
    void validateUserForSignup_WithValidData_ShouldNotThrowException() {
        String email = "new@example.com";
        String password = "securePassword";

        when(userRepository.existsByEmail(email)).thenReturn(false);

        userHelper.validateUserForSignup(email, password);
        verify(userRepository).existsByEmail(email);
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when email exists")
    void validateUserForSignup_WithExistingEmail_ShouldThrowException() {
        String email = "existing@example.com";
        String password = "password123";

        when(userRepository.existsByEmail(email)).thenReturn(true);
        when(messageHelper.getMessage("user.register.not_available")).thenReturn("Registration not available");

        assertThatThrownBy(() -> userHelper.validateUserForSignup(email, password))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when password is too short")
    void validateUserForSignup_WithShortPassword_ShouldThrowException() {
        String email = "valid@example.com";
        String password = "123"; // Too short

        when(messageHelper.getMessage("user.register.password_too_short")).thenReturn("Too short");

        assertThatThrownBy(() -> userHelper.validateUserForSignup(email, password))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
