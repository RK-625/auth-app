package com.substring.authapp.controllers;


import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;


    // create a user
    @PostMapping
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto){
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userDto));
    }

    // get all user api
    @GetMapping
    public ResponseEntity<Iterable<UserDto>> getAllUsers(){
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUser(@PathVariable String userId){
        return ResponseEntity.ok(userService.getUserById(userId));
    }
    // get the user from the email
    @GetMapping("/email/{emailId}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String emailId){
        return ResponseEntity.ok(userService.getUserByEmail(emailId));
    }

    @DeleteMapping("/{userId}")
    public void deleteUserById(@PathVariable String userId){
        userService.deleteUser(userId);
    }

    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(@PathVariable String userId, @RequestBody UserDto userDto){
        return ResponseEntity.ok(userService.updateUser(userDto,userId));
    }
}
