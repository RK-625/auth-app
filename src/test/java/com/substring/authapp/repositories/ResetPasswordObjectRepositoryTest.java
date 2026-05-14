package com.substring.authapp.repositories;

import com.substring.authapp.entities.ResetPasswordObject;
import com.substring.authapp.entities.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class ResetPasswordObjectRepositoryTest {

    @Autowired
    private ResetPasswordObjectRepository resetPasswordObjectRepository;

    @Autowired
    private UserRepository userRepository;

    private User testUser;
    private ResetPasswordObject testResetObject;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setEmail("test@example.com");
        testUser.setPassword("hashedPassword");
        testUser = userRepository.save(testUser);

        testResetObject = new ResetPasswordObject(testUser, "123456", UUID.randomUUID(), 3600);
        testResetObject = resetPasswordObjectRepository.save(testResetObject);
    }

    @Test
    void existsByUserAndOtpAndResetToken_ShouldReturnTrueIfMatches() {
        boolean exists = resetPasswordObjectRepository.existsByUserAndOtpAndResetToken(
                testUser, "123456", testResetObject.getResetToken());
        assertThat(exists).isTrue();
    }

    @Test
    void existsByUserAndOtpAndResetToken_ShouldReturnFalseIfNotMatches() {
        boolean exists = resetPasswordObjectRepository.existsByUserAndOtpAndResetToken(
                testUser, "wrong", testResetObject.getResetToken());
        assertThat(exists).isFalse();
    }

    @Test
    void findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual_ShouldReturnIfValid() {
        Optional<ResetPasswordObject> result = resetPasswordObjectRepository.findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(
                testUser, "123456", Instant.now().minusSeconds(10));
        assertThat(result).isPresent();
        assertThat(result.get().getOtp()).isEqualTo("123456");
    }

    @Test
    void findByUserAndExpiresAtGreaterThan_ShouldReturnIfValid() {
        Optional<ResetPasswordObject> result = resetPasswordObjectRepository.findByUserAndExpiresAtGreaterThan(
                testUser, Instant.now().minusSeconds(10));
        assertThat(result).isPresent();
    }

    @Test
    void findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken_ShouldReturnIfValid() {
        testResetObject.setUsed(true);
        resetPasswordObjectRepository.save(testResetObject);

        Optional<ResetPasswordObject> result = resetPasswordObjectRepository.findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(
                testUser, Instant.now().minusSeconds(10), "123456", testResetObject.getResetToken());
        assertThat(result).isPresent();
    }

    @Test
    void deleteAllByUser_ShouldRemoveAllRecordsForUser() {
        resetPasswordObjectRepository.deleteAllByUser(testUser);
        assertThat(resetPasswordObjectRepository.findAll()).isEmpty();
    }

    @Test
    void deleteByExpiresAtBefore_ShouldRemoveExpiredRecords() {
        testResetObject.setExpiresAt(Instant.now().minusSeconds(3600));
        resetPasswordObjectRepository.save(testResetObject);

        resetPasswordObjectRepository.deleteByExpiresAtBefore(Instant.now());
        assertThat(resetPasswordObjectRepository.findAll()).isEmpty();
    }
}
