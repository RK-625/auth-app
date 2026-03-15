package com.substring.authapp.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.net.http.HttpResponse;

@Service
@Getter
public class CookieService {

    private final String refereshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(@Value("${security.jwt.refresh-token-cookie-name}") String refereshTokenCookieName,@Value("${security.jwt.cookie-http-only}")  boolean cookieHttpOnly, @Value("${security.jwt.cookie-secure}")  boolean cookieSecure, @Value("${security.jwt.cookie-domain}")  String cookieDomain, @Value("${security.jwt.cookie-same-site}")  String cookieSameSite) {
        this.refereshTokenCookieName = refereshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieDomain = cookieDomain;
        this.cookieSameSite = cookieSameSite;
    }

    ///  create method to attach cookie to the response
    public void attachRefreshCookie(HttpServletResponse response, String value , int maxAge){
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(refereshTokenCookieName, value).httpOnly(cookieHttpOnly).secure(cookieSecure).path("/").maxAge(maxAge).sameSite(cookieSameSite);

        if(cookieDomain!=null && !cookieDomain.isBlank()){
            cookieBuilder.domain(cookieDomain);
        }
        ResponseCookie cookie = cookieBuilder.build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    ///  clear referesh token in the cookies of the response here
    public void clearRefreshCookie(HttpServletResponse response){
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(refereshTokenCookieName,"").httpOnly(cookieHttpOnly).secure(cookieSecure).path("/").maxAge(0).sameSite(cookieSameSite);
        if(cookieDomain!=null && cookieDomain.isBlank()){
            cookieBuilder.domain(cookieDomain);
        }
        ResponseCookie cookie = cookieBuilder.build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void addNoStoreHeadersToResponse(HttpServletResponse response){
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
