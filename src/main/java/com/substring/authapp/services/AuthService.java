package com.substring.authapp.services;

import com.substring.authapp.dtos.UserDto;

public interface AuthService {
    UserDto signupUser(UserDto userDto);
    // login user
}
