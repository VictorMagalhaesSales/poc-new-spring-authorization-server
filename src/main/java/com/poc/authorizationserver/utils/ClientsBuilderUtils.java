package com.poc.authorizationserver.utils;

import java.time.Duration;
import java.util.UUID;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

public class ClientsBuilderUtils {
	
	public static RegisteredClient secretPostCredentials() {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-post")
				.clientSecret("{noop}my-secret-post")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read").scope("write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
	}
	
	public static RegisteredClient secretBasicCredentials() {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-basic")
				.clientSecret("{noop}my-secret-basic")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
	}
	
	public static RegisteredClient secretBasicAuthCode() {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-basic-code")
				.clientSecret("{noop}my-client-basic-code")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("https://oidcdebugger.com/debug")
				.redirectUri("https://oauth.pstmn.io/v1/callback")
				.scope("read")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
	}
	
	public static RegisteredClient secretBasicAuthCodeWithRefresh() {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-basic-code-refresh")
				.clientSecret("{noop}my-client-basic-code-refresh")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("https://oidcdebugger.com/debug")
				.scope("read")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				
				.tokenSettings(TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(5))
						.refreshTokenTimeToLive(Duration.ofDays(1))
						.reuseRefreshTokens(false)
						.build())
				
				.build();
	}

}
