package com.substring.authapp.controllers;

import com.substring.authapp.dtos.LoginRequest;
import com.substring.authapp.dtos.RefreshTokenRequest;
import com.substring.authapp.dtos.TokenResponse;
import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RefreshTokenRepositry;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.CookieService;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    public final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RefreshTokenRepositry refreshTokenRepositry;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;
    private final Logger logger = org.slf4j.LoggerFactory.getLogger(AuthController.class);
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response){
        Authentication authentication = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(() -> new BadCredentialsException("Invalid Username or Password"));
        if(user.isEnabled() == false){
            throw new DisabledException("User is disabled"); 
        }
        // generate the token for the user trying to login 
        String accessToken = jwtService.generateAccessToken(user);
        // also generate the referesh token
        String refereshTokenJti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOb = RefreshToken.builder().jti(refereshTokenJti).user(user).createdAt(Instant.now()).expiresAt(Instant.now().plusSeconds(jwtService.getRefereshTtlSeconds())).revoked(false).build();
        refreshTokenRepositry.save(refreshTokenOb);
        String refreshToken = jwtService.generateRefereshToken(user, refereshTokenJti);

        // Use the Cookie Service to set the cookie

        cookieService.attachRefreshCookie(response,refreshToken,(int)jwtService.getAccessTtlSeconds());
        cookieService.addNoStoreHeadersToResponse(response);
        TokenResponse tokenResponse = TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTtlSeconds(), "Bearer", modelMapper.map(user, UserDto.class));
        return ResponseEntity.ok(tokenResponse);
    }

    // do the authentication here and rethorw the error
    private Authentication authenticate(LoginRequest loginRequest){
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(),loginRequest.password()));
        }
        catch (Exception e) {
            throw new BadCredentialsException("Invalid Username or Password");
        }
    }


    // create access and refresh token
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody(required = false) RefreshTokenRequest body,HttpServletResponse response, HttpServletRequest request){

        String refreshToken  = readRefreshTokenRequest(body,request).orElseThrow(() -> new BadCredentialsException("Invalid Refresh Token"));

        if(!jwtService.isRefreshToken(refreshToken)) throw new BadCredentialsException("Invalid refresh token invalid 12");

        String jti = jwtService.getJti(refreshToken);
        UUID useriD = jwtService.getUseriD(refreshToken);

        RefreshToken refreshTokenOb = refreshTokenRepositry.findByJti(jti).orElseThrow(() -> new BadCredentialsException("The Refresh Token is missing in the Database"));
        if(refreshTokenOb.isRevoked()) throw new BadCredentialsException("The Refresh Token is revoked");
        if(refreshTokenOb.getExpiresAt().isBefore(Instant.now())) throw new BadCredentialsException("The Refresh Token is expired");
        if(refreshTokenOb.getUser().getId().equals(useriD) == false) throw new BadCredentialsException("The Refresh Token is not valid for the user");

        // refersh token needs to revoked and rotated
        refreshTokenOb.setRevoked(false);
        String newJti  = UUID.randomUUID().toString();
        refreshTokenOb.setReplacedByToken(newJti);
        refreshTokenRepositry.save(refreshTokenOb);
        // crate the new refresh token
        String newAccessToken = jwtService.generateAccessToken(refreshTokenOb.getUser());
        String newRefreshToken = jwtService.generateRefereshToken(refreshTokenOb.getUser(),newJti);
        RefreshToken newRefreshTokenOb = RefreshToken.builder().jti(newJti).revoked(false).user(refreshTokenOb.getUser()).createdAt(Instant.now()).expiresAt(Instant.now().plusSeconds(jwtService.getRefereshTtlSeconds())).build();
        refreshTokenRepositry.save(newRefreshTokenOb);
        // add the new refresh token to the cookies here
        cookieService.attachRefreshCookie(response,newRefreshToken,(int)jwtService.getAccessTtlSeconds());
        cookieService.addNoStoreHeadersToResponse(response);
        // new Token Response here
        TokenResponse tokenResponse = TokenResponse.of(newAccessToken, newRefreshToken, jwtService.getAccessTtlSeconds(), "Bearer", modelMapper.map(refreshTokenOb.getUser(), UserDto.class));
        return ResponseEntity.ok(tokenResponse);
    }

    private Optional<String> readRefreshTokenRequest(RefreshTokenRequest body, HttpServletRequest request) {
        if(request.getCookies() != null){
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName()
                            .equals(cookieService.getRefereshTokenCookieName()))
                    .map(Cookie::getValue)
                    .filter(token -> !token.isBlank())
                    .findFirst();
            logger.info("The refresh token is not in the cookies");
            if(fromCookie.isPresent()) return fromCookie;
        }
        if(body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) return Optional.of(body.refreshToken());
        return Optional.empty();
    }


    // logout the user
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody(required = false) RefreshTokenRequest body,HttpServletRequest request,HttpServletResponse response){
        // make the change in the referesh token database here
        String refreshtoken = readRefreshTokenRequest(body,request).orElseThrow(() -> new BadCredentialsException("Invalid Refresh Token"));
        if(!jwtService.isRefreshToken(refreshtoken)) throw new BadCredentialsException("Invalid Refresh Token 123");
        String jti = jwtService.getJti(refreshtoken);
        RefreshToken refreshTokenOb = refreshTokenRepositry.findByJti(jti).orElseThrow(() -> new BadCredentialsException("The Refresh Token is missing in the Database"));
        refreshTokenOb.setRevoked(true);
        refreshTokenRepositry.save(refreshTokenOb);
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeadersToResponse(response);
        SecurityContextHolder.clearContext();
        // done here the cookies will be erased now
        return ResponseEntity.noContent().build();
    }

    // create a new user
    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
