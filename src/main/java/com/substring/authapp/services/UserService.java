package com.substring.authapp.services;

import com.substring.authapp.dtos.UserDto;
import java.util.UUID;

public interface UserService {

    UserDto createUser(UserDto userDto);

    UserDto getUserByEmail(String email);

    UserDto updateUser(UserDto userDto, UUID userId);

    void deleteUser(UUID userId);

    UserDto getUserById(UUID userId);

    Iterable<UserDto> getAllUsers();
}
