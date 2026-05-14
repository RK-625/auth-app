package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.admin.AdminUserCreateRequest;
import com.substring.authapp.dtos.admin.ManagementUserResponse;
import com.substring.authapp.dtos.user.AuthUserResponse;
import com.substring.authapp.dtos.user.UserUpdateRequest;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private MessageHelper messageHelper;

    @Mock
    private UserHelper userHelper;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private UserServiceImpl userService;

    @Test
    void deleteUser_ShouldSetEnabledToFalse_WhenUserExists() {
        // Arrange
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .enabled(true)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        // Act
        userService.deleteUser(userId);

        // Assert
        assertThat(user.isEnabled()).as("User should be soft-deleted by setting enabled to false").isFalse();
        // Verify delete is never called on repository
        verify(userRepository, never()).delete(any());
        verify(userRepository, never()).deleteById(any());
    }

    @Test
    void getAllUsers_ShouldReturnOnlyEnabledUsers() {
        // Arrange
        User enabledUser1 = User.builder().id(UUID.randomUUID()).enabled(true).build();
        User enabledUser2 = User.builder().id(UUID.randomUUID()).enabled(true).build();
        User disabledUser = User.builder().id(UUID.randomUUID()).enabled(false).build();

        when(userRepository.findAll()).thenReturn(List.of(enabledUser1, disabledUser, enabledUser2));
        when(modelMapper.map(any(User.class), eq(ManagementUserResponse.class)))
                .thenReturn(new ManagementUserResponse());

        // Act
        Iterable<ManagementUserResponse> result = userService.getAllUsers();

        // Assert
        List<ManagementUserResponse> resultList = (List<ManagementUserResponse>) result;
        assertThat(resultList).as("Should only return enabled users").hasSize(2);
        
        // Verify modelMapper is only called twice (for the two enabled users)
        verify(modelMapper, times(2)).map(any(User.class), eq(ManagementUserResponse.class));
        verify(modelMapper, never()).map(disabledUser, ManagementUserResponse.class);
    }

    @Test
    void createUser_ShouldAssignRoleAdminAndSaveUser() {
        // Arrange
        AdminUserCreateRequest request = new AdminUserCreateRequest();
        request.setEmail("admin@example.com");
        request.setPassword("securePassword");
        request.setName("Admin User");

        Role adminRole = new Role(UUID.randomUUID(), UserRole.ROLE_ADMIN);

        when(passwordEncoder.encode("securePassword")).thenReturn("hashedPassword");
        when(roleRepository.findByName(UserRole.ROLE_ADMIN)).thenReturn(Optional.of(adminRole));
        
        User savedUser = User.builder()
                .id(UUID.randomUUID())
                .email(request.getEmail())
                .name(request.getName())
                .roles(Set.of(adminRole))
                .provider(Provider.ORGANIZATION)
                .enabled(true)
                .build();
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(modelMapper.map(savedUser, ManagementUserResponse.class))
                .thenReturn(new ManagementUserResponse());

        // Act
        userService.createUser(request);

        // Assert
        verify(userHelper).validateUserForSignup(request.getEmail(), request.getPassword());
        
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        
        User capturedUser = userCaptor.getValue();
        assertThat(capturedUser.getEmail()).isEqualTo("admin@example.com");
        assertThat(capturedUser.getPassword()).isEqualTo("hashedPassword");
        assertThat(capturedUser.getProvider()).isEqualTo(Provider.ORGANIZATION);
        assertThat(capturedUser.isEnabled()).isTrue();
        assertThat(capturedUser.getRoles()).as("Created user should have ROLE_ADMIN").contains(adminRole);
    }

    @Test
    void updateUser_WithExistingUser_ShouldModifyAllowedFields() {
        // Arrange
        UUID userId = UUID.randomUUID();
        User existingUser = User.builder()
                .id(userId)
                .name("Old Name")
                .image("old-image.png")
                .build();

        UserUpdateRequest request = new UserUpdateRequest();
        request.setName("New Name");
        request.setImage("new-image.png");

        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
        when(userRepository.save(existingUser)).thenReturn(existingUser);
        when(modelMapper.map(existingUser, AuthUserResponse.class)).thenReturn(new AuthUserResponse());

        // Act
        userService.updateUser(request, userId);

        // Assert
        assertThat(existingUser.getName()).isEqualTo("New Name");
        assertThat(existingUser.getImage()).isEqualTo("new-image.png");
        verify(userRepository).save(existingUser);
    }

    @Test
    void getUserByEmail_WhenNotFound_ShouldThrowResourceNotFoundException() {
        // Arrange
        String email = "missing@example.com";
        when(userHelper.findUserByEmailOrThrow(eq(email), any(ResourceNotFoundException.class)))
                .thenThrow(new ResourceNotFoundException("User not found"));

        // Act & Assert
        assertThatThrownBy(() -> userService.getUserByEmail(email))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void getUserById_HappyPath() {
        // Arrange
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).email("test@test.com").build();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(modelMapper.map(user, ManagementUserResponse.class)).thenReturn(new ManagementUserResponse());

        // Act
        ManagementUserResponse result = userService.getUserById(userId);

        // Assert
        assertThat(result).isNotNull();
        verify(userRepository).findById(userId);
    }

    @Test
    void deleteUser_WhenNotFound_ShouldThrowException() {
        // Arrange
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());
        when(messageHelper.getMessage("user.profile.not_found")).thenReturn("Not found");

        // Act & Assert
        assertThatThrownBy(() -> userService.deleteUser(userId))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void updateUser_WhenNotFound_ShouldThrowException() {
        // Arrange
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());
        when(messageHelper.getMessage("user.profile.not_found")).thenReturn("Not found");

        // Act & Assert
        assertThatThrownBy(() -> userService.updateUser(new UserUpdateRequest(), userId))
                .isInstanceOf(ResourceNotFoundException.class);
    }
}
