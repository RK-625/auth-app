package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.User;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        // doing the necessaru validation
        if(userDto.getEmail() == null || userDto.getEmail().isEmpty() || userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is empty");
        }
        if(userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("Email already exists");
        }
        User user = modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider() == null ? Provider.LOCAL : userDto.getProvider());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        User savedUser = userRepository.save(user);
        //TODO:Assign the role the user object here
        return modelMapper.map(savedUser,UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        // do the necessary validatoion for the email before the checking it
        if(email == null || email.isBlank()){
            throw new IllegalArgumentException("Email is empty");
        }
        User user = userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("User not found with the given Email"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        User oldUser = userRepository.findById(uuid).orElseThrow(() -> new ResourceNotFoundException("User not found with the given Id"));
        // we not going to let the user update the email
        if(userDto.getProvider() != null) oldUser.setProvider(userDto.getProvider());
        if(userDto.getName() != null) oldUser.setName(userDto.getName());
        if(userDto.isEnabled()) oldUser.setEnabled(userDto.isEnabled());
        if(userDto.getImage() != null) oldUser.setImage(userDto.getImage());
        if(userDto.getPassword() != null) oldUser.setPassword(userDto.getPassword());
        User updatedUser = userRepository.save(oldUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        // FIRST THE UUID SHOULD EXIST IN THE DATABASE
        userRepository.findById(uuid).orElseThrow(()-> new ResourceNotFoundException("User not found with the given Id"));
        userRepository.deleteUserById(uuid);
    }

    @Override
    public UserDto getUserById(String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uuid).orElseThrow(() -> new ResourceNotFoundException("User not found with the given Id"));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository
                .findAll()
                .stream()
                .map((element) -> modelMapper.map(element, UserDto.class))
                .toList();
    }
}

