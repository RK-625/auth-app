package com.substring.authapp.security;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Authentication success");
        logger.info(authentication.toString());
        logger.info("Success URI: {}", request.getRequestURI());
        logger.info("Query: {}", request.getQueryString());
        logger.info("Full URL: {}", request.getRequestURL());
        response.getWriter().write("Authentication success");
        
//        // this gives the principal of the Oauth user here
//         OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
//
//        Map<String, Object> attributes = oAuth2User.getAttributes();
//        String name = attributes.get("name").toString();
        // getting the data from the
    }
}
