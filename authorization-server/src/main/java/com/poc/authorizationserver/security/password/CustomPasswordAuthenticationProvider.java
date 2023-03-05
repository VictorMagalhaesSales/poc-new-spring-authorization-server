package com.poc.authorizationserver.security.password;

import java.security.Principal;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * Uma {@link AuthenticationProvider} implementação para o fluxo depreciado Password.
 */
public final class CustomPasswordAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	
	private final Log logger = LogFactory.getLog(getClass());
	
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
	private final DaoAuthenticationProvider daoAuthProvider;

	public CustomPasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, DaoAuthenticationProvider daoAuthProvider) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		Assert.notNull(daoAuthProvider, "daoAuthProvider cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
		this.daoAuthProvider = daoAuthProvider;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		CustomPasswordAuthenticationToken passwordAuthentication = (CustomPasswordAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(passwordAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		authenticateUser(passwordAuthentication);

		if (this.logger.isTraceEnabled())
			this.logger.trace("Retrieved registered client");

		validateAuthorizedGrantTypes(registeredClient);
		Set<String> authorizedScopes = validateAndReturnAuthorizedScopes(passwordAuthentication, registeredClient);

		if (this.logger.isTraceEnabled())
			this.logger.trace("Validated token request parameters");
		
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(CustomAuthorizationGrantType.PASSWORD)
				.authorizationGrant(passwordAuthentication);
		
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(CustomAuthorizationGrantType.PASSWORD)
				.attribute(Principal.class.getName(), authentication)
				.authorizedScopes(authorizedScopes);
		
		OAuth2AccessToken accessToken =  generateAccessToken(tokenContextBuilder, authorizationBuilder);
		OAuth2RefreshToken refreshToken = 
				generateRefreshToken(tokenContextBuilder, authorizationBuilder, clientPrincipal, registeredClient);

		this.authorizationService.save(authorizationBuilder.build());
		
		if (this.logger.isTraceEnabled())
			this.logger.trace("Saved authorization & authenticated token request");

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
	}

	private void authenticateUser(CustomPasswordAuthenticationToken passwordAuthentication) {
		String username = (String) passwordAuthentication.getAdditionalParameters().get("username");
		String password = (String)  passwordAuthentication.getAdditionalParameters().get("password");
		Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
		daoAuthProvider.authenticate(userAuth);
	}

	private OAuth2AccessToken generateAccessToken(DefaultOAuth2TokenContext.Builder tokenContextBuilder,
			OAuth2Authorization.Builder authorizationBuilder) {
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled())
			this.logger.trace("Generated access token");

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken, (metadata) ->
					metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
		} else {
			authorizationBuilder.accessToken(accessToken);
		}
		return accessToken;
	}

	private OAuth2RefreshToken generateRefreshToken(DefaultOAuth2TokenContext.Builder tokenContextBuilder,
			OAuth2Authorization.Builder authorizationBuilder, OAuth2ClientAuthenticationToken clientPrincipal,
			RegisteredClient registeredClient) {
		OAuth2TokenContext tokenContext;
		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
				// Do not issue refresh token to public client
				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Generated refresh token");
			}

			refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(refreshToken);
		}
		return refreshToken;
	}

	private void validateAuthorizedGrantTypes(RegisteredClient registeredClient) {
		if (!registeredClient.getAuthorizationGrantTypes().contains(CustomAuthorizationGrantType.PASSWORD)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}
	}

	private Set<String> validateAndReturnAuthorizedScopes(CustomPasswordAuthenticationToken passwordAuthentication,
			RegisteredClient registeredClient) {
		Set<String> authorizedScopes = Collections.emptySet();
		if (!CollectionUtils.isEmpty(passwordAuthentication.getScopes())) {
			for (String requestedScope : passwordAuthentication.getScopes()) {
				if (!registeredClient.getScopes().contains(requestedScope)) {
					throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
				}
			}
			authorizedScopes = new LinkedHashSet<>(passwordAuthentication.getScopes());
		}
		return authorizedScopes;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return CustomPasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}


}
