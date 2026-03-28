package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.services.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Service to handle registration and authentication related operations.
 */
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final UserHelper userHelper;
    private final MessageSource messageSource;
    private final RoleRepository roleRepository;

    /**
     * Registers a new user account, ensuring the password is encrypted and default roles are assigned.
     * This method handles manual web signups (LOCAL provider).
     */
    @Override
    public UserDto signupUser(UserDto userDto) {
        // 1. Validate business constraints (email existence, etc.)
        userHelper.validateUserForSignup(userDto);
        
        // 2. Map and prepare the entity
        User user = modelMapper.map(userDto, User.class);
        user.setProvider(Provider.LOCAL);
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        // 3. Initialize roles set and assign default ROLE_USER
        Set<Role> roles = new HashSet<>();
        Role defaultRole = roleRepository.findByName(UserRole.ROLE_USER.name())
                .orElseThrow(() -> new ResourceNotFoundException(msg("role.not_found")));
        roles.add(defaultRole);
        user.setRoles(roles);
        
        // 4. Persist and return the new userdto without the UserId for the safety here
        User savedUser = userRepository.save(user);
        UserDto dto = modelMapper.map(savedUser, UserDto.class);
        dto.setId(null);
        return dto;
    }
    private String msg(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
