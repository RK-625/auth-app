package com.substring.authapp.services;

import com.substring.authapp.dtos.UserDto;

public interface UserService {

    UserDto createUser(UserDto userDto);

    UserDto getUserByEmail(String email);

    UserDto updateUser(UserDto userDto, String userId);

    void deleteUser(String userId);

    UserDto getUserById(String userId);

    Iterable<UserDto> getAllUsers();
}
