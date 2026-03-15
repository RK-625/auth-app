package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl  implements AuthService {

    private final UserService userService;
    private PasswordEncoder passwordEncoder;
    @Override
    public UserDto registerUser(UserDto userDto) {
        // hash the password for the userDto first
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        return userService.createUser(userDto);
    }
}
