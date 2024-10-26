package com.example.oauth2authorizationserver.Controller;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    /*
    想要让我的 API Endpoint 受到保护，注意以下：
        1.
        Spring Security 的核心是 Authentication 对象，它代表当前用户的认证状态。
        Spring Security 会检查 SecurityContextHolder 中是否有一个有效的 Authentication 对象
        2.
        如果 SecurityContextHolder.getContext().getAuthentication()
        返回一个有效的 Authentication 对象，并且其 isAuthenticated() 方法返回 true

        3.
        Spring Security 默认的会话管理是基于用户的 Authentication 对象，而不是每次都通过 Access Token 来进行认证。
        因此，在会话有效期间，Spring Security 使用的是会话中的身份验证信息，而不是每次都向资源服务器验证 Access Token
     */

    @GetMapping("/hello")
    public String hello(Authentication authentication){
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            // 获取用户名（可以从 OAuth2 的 Principal 中获取用户信息）
            String username = oauthToken.getPrincipal().getName();
            System.out.println(oauthToken.getPrincipal());
            System.out.println(oauthToken.getPrincipal().getName());
            System.out.println(oauthToken.getCredentials());
            System.out.println(oauthToken.getAuthorities());
            System.out.println(oauthToken.getName());
            return "Hello " + username;
        }
        throw new BadCredentialsException("Wrong credentials");
    }
}
