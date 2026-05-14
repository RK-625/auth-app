package com.substring.authapp.config;

import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DataSeederTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private DataSeeder dataSeeder;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(dataSeeder, "rootEmail", "root@test.com");
        ReflectionTestUtils.setField(dataSeeder, "rootPassword", "rootpass");
    }

    @Test
    void run_ShouldProvisionRolesAndUsers_WhenDatabaseIsEmpty() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");
        
        // Sequential stubbing for findByName:
        // 3 calls from syncRoles (USER, ADMIN, ROOT) -> empty
        // 1 call from injectRootUser (ROOT) -> mockRole
        // 1 call from injectTestUser (USER) -> mockRole
        Role mockRole = Role.builder().name(UserRole.ROLE_ROOT).build();
        when(roleRepository.findByName(any(UserRole.class)))
                .thenReturn(Optional.empty(), Optional.empty(), Optional.empty()) // for syncRoles
                .thenReturn(Optional.of(mockRole)) // for injectRootUser
                .thenReturn(Optional.of(mockRole)); // for injectTestUser

        dataSeeder.run();

        // Assert
        verify(roleRepository, times(3)).save(any(Role.class));
        verify(userRepository, times(2)).save(any(User.class)); // Root + Test User
    }

    @Test
    void run_ShouldBeIdempotent_WhenDataAlreadyExists() {
        // Arrange
        when(roleRepository.findByName(any(UserRole.class))).thenReturn(Optional.of(new Role()));
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // Act
        dataSeeder.run();

        // Assert
        verify(roleRepository, never()).save(any(Role.class));
        verify(userRepository, never()).save(any(User.class));
    }
}
