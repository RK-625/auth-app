package com.substring.authapp.security;


import com.substring.authapp.dtos.TokenResponse;
import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.User;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RefreshTokenRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.provider.GithubService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(OAuth2SuccessHandler.class);
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;
    private final GithubService githubService;
    private final OAuth2AuthorizedClientService authorizedClientService;

    // returns a Map of the attributes
    private Map<Object,Object> fetchAttributes(Authentication authentication){
        Map<Object,Object> res = new HashMap<>();
        // the details
        // the access token to the provider api
        OAuth2User oAuthUser = (OAuth2User) authentication.getPrincipal();
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        // provider --> provider
        Provider provider = Provider.LOCAL;
        if(authentication instanceof OAuth2AuthenticationToken){
            switch (token.getAuthorizedClientRegistrationId()){
                case "google" : provider = (Provider.GOOGLE); break;
                case "github" : provider = (Provider.GITHUB); break;
                case "facebook" : provider = (Provider.FACEBOOK); break;
                default : provider = (Provider.LOCAL);
            }
        }
        res.put("provider",provider);
        // 1. name-->  name
        res.put("name",oAuthUser.getAttribute("name"));
        //2. image--> image
        String image = provider.equals(Provider.GOOGLE) ? oAuthUser.getAttribute("picture")
                : provider.equals(Provider.GITHUB) ? oAuthUser.getAttribute("avatar_url")
                : "" ;
        res.put("image", image);
        //3. email--> email
        String email = oAuthUser.getAttribute("email") == null ? githubService.getEmailFromGithub(authorizedClientService.loadAuthorizedClient(token.getAuthorizedClientRegistrationId(), token.getName())) : oAuthUser.getAttribute("email");
        res.put("email",email);
        return res;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Authentication success");
        logger.info(authentication.toString());
        logger.info("Success URI: {}", request.getRequestURI());
        logger.info("Query: {}", request.getQueryString());
        logger.info("Full URL: {}", request.getRequestURL());
        response.getWriter().write("Authentication success");

        Map<Object,Object> attributes = fetchAttributes(authentication);

        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String image =(String) attributes.get("image");
        Provider provider = (Provider) attributes.get("provider");

        // First Check if the user is already registered in the database
        User user;
        if(userRepository.existsByEmail(email) == false){
            user = User.builder().email(email).name(name).image(image).enabled(true).createdAt(Instant.now()).updatedAt(Instant.now()).provider(provider).build();
            userRepository.save(user);
        }
        else user = userRepository.findByEmail(email).get();

        // generate the token for the user trying to login
        String accessToken = jwtService.generateAccessToken(user);
        // also generate the referesh token
        String refereshTokenJti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOb = RefreshToken.builder().jti(refereshTokenJti).user(user).createdAt(Instant.now()).expiresAt(Instant.now().plusSeconds(jwtService.getRefereshTtlSeconds())).revoked(false).build();
        refreshTokenRepository.save(refreshTokenOb);
        String refreshToken = jwtService.generateRefereshToken(user, refereshTokenJti);
        // Use the Cookie Service to set the cookie
        cookieService.attachRefreshCookie(response,refreshToken,(int)jwtService.getAccessTtlSeconds());
        cookieService.addNoStoreHeadersToResponse(response);
        TokenResponse tokenResponse = TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTtlSeconds(), "Bearer", modelMapper.map(user, UserDto.class));
        logger.info("Token Response: {}", tokenResponse);
        logger.info("Oauth2 is successfull here ");
    }
}
