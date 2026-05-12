package com.substring.authapp.repositories;

import com.substring.authapp.entities.SignUpObject;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class SignUpObjectRepositoryTest {

    @Autowired
    private SignUpObjectRepository repository;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    void findByEmailAndOtpAndExpiresAtGreaterThan_ShouldReturnEntityWhenValid() {
        // Given
        String email = "valid@test.com";
        String otp = "123456";
        UUID token = UUID.randomUUID();
        SignUpObject signup = new SignUpObject(email, otp, token, 300); // 5 mins TTL
        entityManager.persist(signup);
        entityManager.flush();

        // When
        Optional<SignUpObject> result = repository.findByEmailAndOtpAndExpiresAtGreaterThan(email, otp, Instant.now());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo(email);
    }

    @Test
    void findByEmailAndOtpAndExpiresAtGreaterThan_ShouldReturnEmptyWhenExpired() {
        // Given
        String email = "expired@test.com";
        String otp = "123456";
        UUID token = UUID.randomUUID();
        SignUpObject signup = new SignUpObject(email, otp, token, -300); // Expired 5 mins ago
        entityManager.persist(signup);
        entityManager.flush();

        // When
        Optional<SignUpObject> result = repository.findByEmailAndOtpAndExpiresAtGreaterThan(email, otp, Instant.now());

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void deleteByExpiresAtBefore_ShouldPurgeStaleRecords() {
        // Given
        SignUpObject valid = new SignUpObject("valid@test.com", "111111", UUID.randomUUID(), 300);
        SignUpObject expired = new SignUpObject("expired@test.com", "222222", UUID.randomUUID(), -300);
        
        entityManager.persist(valid);
        entityManager.persist(expired);
        entityManager.flush();

        // When
        repository.deleteByExpiresAtBefore(Instant.now());
        entityManager.flush();
        entityManager.clear();

        // Then
        assertThat(repository.findByEmail("valid@test.com")).isPresent();
        assertThat(repository.findByEmail("expired@test.com")).isEmpty();
    }
}
