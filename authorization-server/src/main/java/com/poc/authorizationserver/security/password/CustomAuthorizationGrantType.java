package com.poc.authorizationserver.security.password;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class CustomAuthorizationGrantType {

	public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");
}
