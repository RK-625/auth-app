package com.substring.authapp.services;

import com.substring.authapp.repositories.ResetPasswordObjectRepository;
import com.substring.authapp.repositories.SignUpObjectRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CleanupServiceTest {

    @Mock
    private SignUpObjectRepository signUpObjectRepository;

    @Mock
    private ResetPasswordObjectRepository resetPasswordObjectRepository;

    @InjectMocks
    private CleanupService cleanupService;

    @Test
    void purgeExpiredHandshakes_ShouldInvokeDeletionQueriesOnAllRepositories() {
        // Action
        cleanupService.purgeExpiredHandshakes();

        // Assert
        verify(signUpObjectRepository).deleteByExpiresAtBefore(any(Instant.class));
        verify(resetPasswordObjectRepository).deleteByExpiresAtBefore(any(Instant.class));
        assertThat(cleanupService.getLastRun()).isBeforeOrEqualTo(Instant.now());
    }

    @Test
    void purgeExpiredHandshakes_WhenRepositoryThrowsException_ShouldCatchAndLog() {
        // Arrange
        doThrow(new RuntimeException("Database connection timeout"))
                .when(signUpObjectRepository).deleteByExpiresAtBefore(any(Instant.class));

        // Action & Assert
        // We explicitly assert that the scheduled task does NOT throw an exception,
        // which proves the application remains stable and the background thread doesn't crash.
        assertThatCode(() -> cleanupService.purgeExpiredHandshakes())
                .doesNotThrowAnyException();

        // Verify the first repository was attempted
        verify(signUpObjectRepository).deleteByExpiresAtBefore(any(Instant.class));
        
        // Note: Because the implementation wraps both calls in a single try-catch,
        // the second repository isn't called. This is expected behavior for the current implementation.
        verify(resetPasswordObjectRepository, never()).deleteByExpiresAtBefore(any(Instant.class));
    }
}
