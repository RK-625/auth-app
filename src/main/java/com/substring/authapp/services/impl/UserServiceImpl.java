package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.User;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.services.UserService;
import jakarta.transaction.Transactional;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Core implementation for user-related business logic and persistence.
 */
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final MessageSource messageSource;

    public UserServiceImpl(UserRepository userRepository, 
                           ModelMapper modelMapper, 
                           PasswordEncoder passwordEncoder, 
                           MessageSource messageSource) {
        this.userRepository = userRepository;
        this.modelMapper = modelMapper;
        this.passwordEncoder = passwordEncoder;
        this.messageSource = messageSource;
    }

    /**
     * Creates and persists a new user with an encoded password.
     */
    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException(msg("user.register.email_required"));
        }
        
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException(msg("user.register.email_exists"));
        }

        User user = modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider() == null ? Provider.LOCAL : userDto.getProvider());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        
        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser, UserDto.class);
    }

    /**
     * Retrieves a user by their email address.
     */
    @Override
    public UserDto getUserByEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(msg("user.register.email_required"));
        }
        
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException(msg("user.profile.not_found")));
        return modelMapper.map(user, UserDto.class);
    }

    /**
     * Updates an existing user's profile details.
     */
    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        User oldUser = userRepository.findById(uuid)
                .orElseThrow(() -> new ResourceNotFoundException(msg("user.profile.not_found")));
        
        // Update only allowed fields
        if (userDto.getProvider() != null) oldUser.setProvider(userDto.getProvider());
        if (userDto.getName() != null) oldUser.setName(userDto.getName());
        if (userDto.getImage() != null) oldUser.setImage(userDto.getImage());
        if (userDto.getPassword() != null) oldUser.setPassword(passwordEncoder.encode(userDto.getPassword()));
        
        oldUser.setEnabled(userDto.isEnabled());
        
        User updatedUser = userRepository.save(oldUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

    /**
     * Permanently removes a user from the system.
     */
    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        if (!userRepository.existsById(uuid)) {
            throw new ResourceNotFoundException(msg("user.profile.not_found"));
        }
        userRepository.deleteUserById(uuid);
    }

    /**
     * Retrieves a single user by their unique identifier.
     */
    @Override
    public UserDto getUserById(String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uuid)
                .orElseThrow(() -> new ResourceNotFoundException(msg("user.profile.not_found")));
        return modelMapper.map(user, UserDto.class);
    }

    /**
     * Returns a list of all registered users in the system.
     */
    @Override
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(u -> modelMapper.map(u, UserDto.class))
                .toList();
    }

    private String msg(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
