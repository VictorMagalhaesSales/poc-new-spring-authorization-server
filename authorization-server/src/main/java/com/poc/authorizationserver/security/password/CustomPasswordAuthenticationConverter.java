package com.poc.authorizationserver.security.password;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Classe responsável por extrair dados de autenticação da {@link HttpServletRequest}, pelo fluxo "Password"
 * para construir {@link OAuth2PasswordAuthenticationToken} utilizado para autenticar o usuário.
 */
public final class CustomPasswordAuthenticationConverter implements AuthenticationConverter {
	public static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		if(!validateGrantType(request))
			return null;

		MultiValueMap<String, String> parameters = getParameters(request);
		String scope = validateAndReturnScopes(parameters);

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
		Set<String> requestedScopes = parseScopesToSet(scope);
		Map<String, Object> additionalParameters = getAdditionalParameters(parameters);
		
		return new CustomPasswordAuthenticationToken(
				clientPrincipal, requestedScopes, additionalParameters);
	}

	private String validateAndReturnScopes(MultiValueMap<String, String> parameters) {
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		
		if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " 
						+ OAuth2ParameterNames.SCOPE, ACCESS_TOKEN_REQUEST_ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}
		return scope;
	}

	private Set<String> parseScopesToSet(String scope) {
		Set<String> requestedScopes = null;
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}
		return requestedScopes;
	}

	private Map<String, Object> getAdditionalParameters(MultiValueMap<String, String> parameters) {
		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, value.get(0));
			}
		});
		return additionalParameters;
	}

	private boolean validateGrantType(HttpServletRequest request) {
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!CustomAuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
			return false;
		}
		return true;
	}

	private MultiValueMap<String, String> getParameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
		parameterMap.forEach((key, values) -> {
			if (values.length > 0) {
				for (String value : values) {
					parameters.add(key, value);
				}
			}
		});
		return parameters;
	}
}
