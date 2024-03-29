package com.poc.authorizationserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.poc.authorizationserver.interceptors.CookieRefreshTokenExtractionInterceptor;
import com.poc.authorizationserver.interceptors.CookieRefreshTokenInsertionInterceptor;
import com.poc.authorizationserver.security.password.CustomPasswordAuthenticationConverter;
import com.poc.authorizationserver.security.password.CustomPasswordAuthenticationProvider;
import com.poc.authorizationserver.utils.ClientsBuilderUtils;
import com.poc.authorizationserver.utils.JwtUtils;

@Configuration
public class AuthorizationServerConfig {
	
	@Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			DaoAuthenticationProvider daoAuthProvider) throws Exception {
		// Default Configurations
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			// Enable OpenID Connnect 1.0
			.oidc(Customizer.withDefaults())

    		.tokenEndpoint(tokenEndpointConfig -> tokenEndpointConfig
        			// Refresh Token in Cookie interceptor
    	    		.accessTokenResponseHandler(new CookieRefreshTokenInsertionInterceptor())
    	    		
    				// Custom "password" flow config
    				.accessTokenRequestConverter(new CustomPasswordAuthenticationConverter())
    				.authenticationProvider(new CustomPasswordAuthenticationProvider(createAuthService(http), createTokenGenerator(http), daoAuthProvider)));

		// Refresh Token in Cookie interceptor
        http.addFilterBefore(new CookieRefreshTokenExtractionInterceptor(), AuthorizationFilter.class);
        
        // Accept access tokens for User Info and/or Client Registration
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder encoder) {	
		return new InMemoryRegisteredClientRepository(
				ClientsBuilderUtils.secretPostCredentials(encoder),
				ClientsBuilderUtils.secretBasicCredentials(encoder),
				ClientsBuilderUtils.secretBasicAuthCode(encoder),
				ClientsBuilderUtils.secretBasicAuthCodeWithRefresh(encoder),
				ClientsBuilderUtils.secretBasicPasswordWithRefresh(encoder));
	}
	
	@Bean 
	public JWKSource<SecurityContext> jwkSource() {
		JWKSet jwkSet = JwtUtils.generateJWKSet();
		return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean 
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	
	/* Utilities methods */
	
	private OAuth2AuthorizationService createAuthService(HttpSecurity httpSecurity) {
		OAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
		httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		return authorizationService;
	}
	
	private OAuth2TokenGenerator<? extends OAuth2Token> createTokenGenerator(HttpSecurity httpSecurity) {
		JWKSource<SecurityContext> jwkSource = jwkSource();
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = 
				new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
		
		httpSecurity.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
		httpSecurity.setSharedObject(JwtGenerator.class, jwtGenerator);
		httpSecurity.setSharedObject(JwtEncoder.class, jwtEncoder);
		return tokenGenerator;
	}

}
