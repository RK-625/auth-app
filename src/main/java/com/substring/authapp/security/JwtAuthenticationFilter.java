package com.substring.authapp.security;

import com.substring.authapp.entities.User;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.hibernate.engine.jdbc.spi.JdbcWrapper;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if(header != null && header.startsWith("Bearer")){
            // the request should be not null and the start with Bearer token
            // this is the jwt token
            String token = header.substring(7);
            logger.info("The token is : {}",token);
            try{
                if(jwtService.isAccessToken(token) == false){
                    // it is not a valid access token
                    filterChain.doFilter(request, response);
                    return;
                }
                Jws<Claims> claims = jwtService.parse(token);
                Claims payload = claims.getPayload();
                String userId = payload.getSubject();
                String jti = payload.getId();
                UUID userUUUID = UserHelper.parseUUID(userId);

                userRepository.findById(userUUUID)
                        .ifPresent(
                                user -> {

                                    // if the user is not enbled then exit here itself
                                    if(user.isEnabled()){
                                        List<GrantedAuthority> authorityList = user.getRoles() == null ? List.of() : user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
                                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user.getEmail(),null,authorityList);
                                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // add the details to authentication object
                                        if(SecurityContextHolder.getContext().getAuthentication() == null){
                                            SecurityContextHolder.getContext().setAuthentication(authentication); //  add  the authentication to the security context
                                        }
                                    }
                                }
                        );
            }
            catch (ExpiredJwtException e){
                request.setAttribute("error", "Token has expired");
            }
            catch (Exception e) {
                request.setAttribute("error", "Token is not valid");
            }

        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // for bboth login and register here
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}
