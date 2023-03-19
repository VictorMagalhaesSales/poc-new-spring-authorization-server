package com.poc.authorizationserver.utils;

import java.time.Duration;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import com.poc.authorizationserver.security.password.CustomAuthorizationGrantType;

public class ClientsBuilderUtils {
	
	public static RegisteredClient secretPostCredentials(PasswordEncoder encoder) {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-post")
				.clientSecret(encoder.encode("my-secret-post"))
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
	
	public static RegisteredClient secretBasicCredentials(PasswordEncoder encoder) {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-basic")
				.clientSecret(encoder.encode("my-secret-basic"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
	}
	
	public static RegisteredClient secretBasicAuthCode(PasswordEncoder encoder) {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-basic-code")
				.clientSecret(encoder.encode("my-client-basic-code"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("https://oidcdebugger.com/debug")
				.redirectUri("https://oauth.pstmn.io/v1/callback")
				.scope("read")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
	}
	
	public static RegisteredClient secretBasicAuthCodeWithRefresh(PasswordEncoder encoder) {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("my-client-basic-code-refresh")
				.clientSecret(encoder.encode("my-client-basic-code-refresh"))
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
	
	public static RegisteredClient secretBasicPasswordWithRefresh(PasswordEncoder encoder) {
		return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("my-client-password")
                .clientSecret(encoder.encode("my-client-password"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                .authorizationGrantType(CustomAuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                
                .tokenSettings(TokenSettings.builder()
	                		.refreshTokenTimeToLive(Duration.ofDays(1))
	                		.reuseRefreshTokens(false).build())
                .build();
	}

}
