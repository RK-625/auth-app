package com.substring.authapp.repositories;

import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    private User testUser;
    private RefreshToken testRefreshToken;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setEmail("refresh@example.com");
        testUser.setPassword("password");
        testUser = userRepository.save(testUser);

        testRefreshToken = RefreshToken.create(testUser, UUID.randomUUID().toString(), 3600);
        testRefreshToken = refreshTokenRepository.save(testRefreshToken);
    }

    @Test
    void findByJti_ShouldReturnToken() {
        Optional<RefreshToken> found = refreshTokenRepository.findByJti(testRefreshToken.getJti());
        assertThat(found).isPresent();
        assertThat(found.get().getJti()).isEqualTo(testRefreshToken.getJti());
    }

    @Test
    void revokeAllByUser_ShouldSetRevokedToTrue() {
        refreshTokenRepository.revokeAllByUser(testUser);
        
        Optional<RefreshToken> token = refreshTokenRepository.findById(testRefreshToken.getId());
        assertThat(token).isPresent();
        assertThat(token.get().isRevoked()).isTrue();
    }
}
