package com.substring.authapp.dtos;

import lombok.Builder;

@Builder
public record TokenResponse(String accessToken,String refreshToken,long expiresIn,String tokenType,UserDto user) {
    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, String tokenType,UserDto user) {
        return new TokenResponse(accessToken, refreshToken, expiresIn, "Bearer", user);
    }
}
