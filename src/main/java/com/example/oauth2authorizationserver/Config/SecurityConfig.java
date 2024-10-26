package com.example.oauth2authorizationserver.Config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.jwtDecoder;

/*
    如何知道用户未验证？
    当用户或客户端访问受保护的资源（例如需要授权的 API 或页面），服务器会检查该请求是否携带了有效的认证信息（如Token）。
    如果没有认证信息或认证信息无效，服务器会将用户重定向到登录页面（如 /login）。

    流程，启动服务器：
    1. 访问
     GET http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&redirect_uri=https://springone.io&scope=openid%20profile
    2. 访问
     POST http://localhost:8080/oauth2/token
     并且在 Body里的 x-www-form-urlencoded
     里写上：
     Key	            Value
     client_id	        client
     client_secret	    secret
     redirect_uri	    https://springone.io
     grant_type	        authorization_code
     code	            code...

     3. 最终会返回类似格式：
     {
        "access_token": "eyJraWQiOi...",
        "scope": "openid profile",
        "id_token": "eyJraWQiO...",
        "token_type": "Bearer",
        "expires_in": 299
     }
     解析一下 id token：
     {
      "sub": "ahsoka",  $$$ Subject: 通常是用户的唯一标识符
      "aud": "client",  $$$ Audience: 受众（Audience），表示该令牌是为哪个客户端或服务生成的
      "azp": "client",  $$$ 授权方（Authorized Party），通常用于 OpenID Connect。它表示该令牌的最终接收方，也就是经过授权的客户端
      "auth_time": 1728597998,  $$$ 自 1970 年 1 月 1 日以来的秒数），表示用户在时间 1728597998（对应某个具体的日期和时间）完成了身份验证
      "iss": "http://localhost:8080",   $$$ 发行者（Issuer），即签发该 JWT 的授权服务器或身份提供者的 URL
      "exp": 1728599838,    $$$ 过期时间
      "iat": 1728598038,    $$$ 签发时间，表示 JWT 是在 1728598038（Unix 时间戳）时签发的。这个字段告诉我们令牌是什么时候生成的
      "jti": "b78f7759-636b-4bdc-b713-152f5ff970e0",   $$$ JWT ID，通常是一个唯一的字符串，用于防止令牌重放攻击
      "sid": "0MfX55NkOBtWvymYOqgy_nkyLhzhWUq-YjN32ahvK2Y"  $$$ session ID
     }


 */
@Configuration
public class SecurityConfig {
    // 注⚠️：当一个请求被某个 SecurityFilterChain 匹配并处理后，不会再进入其他的过滤链

    /*
        处理与授权服务器相关的请求，如 /oauth2/authorize、/oauth2/token 等端点
     */
    @Bean
    // 表示它会首先匹配 http request 和应用到请求中
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        /*
            这行代码应用了 OAuth 2.0 授权服务器的默认安全配置。它会启用授权服务器的端点，
            如 /oauth2/authorize、/oauth2/token、/oauth2/jwks 等。这些端点处理授权、令牌请求和公钥发布
         */
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        /*
            Enable OpenID Connect（OIDC）支持
         */
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(withDefaults());

        http.cors(withDefaults());

        // 处理未经身份验证的请求。如果用户尝试访问授权服务器的端点但未登录，会被重定向到 /login 页面进行身份验证
        http.exceptionHandling(
                e -> e.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")
                )
        );

        return http.build();
    }

    /*
        处理应用程序的其他 HTTP 请求。这些请求与 OAuth 2.0 无关
     */
    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        /*
        http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&redirect_uri=https://springone.io&scope=openid%20profile
         */
        return
            http
                .cors(withDefaults())
                .formLogin(withDefaults())
                .authorizeHttpRequests(
                        auth -> auth.anyRequest().authenticated()
                )
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("ahsoka")
                        .password("{noop}ahsoka")
                        .roles("USER")
                        .authorities("read")
                        .build()
        );
    }

    // 模拟 Client
    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("{noop}secret")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
//                .redirectUri("https://springone.io")
                .redirectUri("http://localhost:5173/redirect")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // 自定义access token，有效期2小时
                .tokenSettings(
                    TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofHours(2))
                    .build()
                )
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    // 模拟 Authorization Server
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey key = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())  // Add key ID for identification
                .build();
        JWKSet set = new JWKSet(key);
        return new ImmutableJWKSet<>(set);
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true); // 允许发送 Cookie
        config.addAllowedOrigin("http://localhost:5173");
        config.addAllowedHeader("*"); // 允许所有请求头
        config.addAllowedMethod("*"); // 允许所有 HTTP 方法（GET, POST, PUT, DELETE, OPTIONS, etc.）

        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
