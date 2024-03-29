package com.poc.authorizationserver.interceptors;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CookieRefreshTokenInsertionInterceptor implements AuthenticationSuccessHandler {
	
	private final HttpMessageConverter<OAuth2AccessTokenResponse> responseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		OAuth2AccessTokenAuthenticationToken tokenAuthentication = (OAuth2AccessTokenAuthenticationToken) authentication;
		OAuth2AccessToken accessToken = tokenAuthentication.getAccessToken();
		OAuth2RefreshToken refreshToken = tokenAuthentication.getRefreshToken();
		Map<String, Object> additionalParams = tokenAuthentication.getAdditionalParameters();
		
		insertRefreshTokenInCookie(refreshToken, request, response);

		OAuth2AccessTokenResponse accessTokenResponse = buildTokenResponse(accessToken, additionalParams);

		this.responseConverter.write(accessTokenResponse, null, new ServletServerHttpResponse(response));
	}

	private OAuth2AccessTokenResponse buildTokenResponse(OAuth2AccessToken accessToken, Map<String, Object> additionalParams) {
		OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
														.withToken(accessToken.getTokenValue())
														.tokenType(accessToken.getTokenType())
														.scopes(accessToken.getScopes());
		
		if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null)
			builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
		if (!CollectionUtils.isEmpty(additionalParams))
			builder.additionalParameters(additionalParams);
		
		return builder.build();
	}
	
	private void insertRefreshTokenInCookie(OAuth2RefreshToken refreshToken, HttpServletRequest req, HttpServletResponse resp) {		
		Cookie cookie = new Cookie("refreshToken", refreshToken.getTokenValue());
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath("/");
		// TODO: put this value in environment variable
		cookie.setMaxAge(2592000);
		resp.addCookie(cookie);
	}

}
