package com.poc.authorizationserver.security.password;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import lombok.Getter;

@Getter
public class CustomPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private static final long serialVersionUID = 1L;
	private final Set<String> scopes;

	public CustomPasswordAuthenticationToken(Authentication clientPrincipal,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(CustomAuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
		this.scopes = Collections.unmodifiableSet(
				scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
	}
	
}
