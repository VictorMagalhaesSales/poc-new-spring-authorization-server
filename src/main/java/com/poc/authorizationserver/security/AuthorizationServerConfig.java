package com.poc.authorizationserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class AuthorizationServerConfig {

	
	@Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		// Default Configurations
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		
		// Enable OpenID Connnect 1.0
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());

		// Redirect to the login page when not authenticated from the authorization endpoint
		http.exceptionHandling(
			exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
		);

		// Accept access tokens for User Info and/or Client Registration
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}

}
