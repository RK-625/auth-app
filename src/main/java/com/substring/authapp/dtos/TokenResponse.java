package com.substring.authapp.dtos;

public record TokenResponse(String accessToken,String refreshToken,long expiresIn,String tokenType,UserDto user) {
    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, String tokenType,UserDto user) {
        return new TokenResponse(accessToken, refreshToken, expiresIn, "Bearer", user);
    }
}
