package com.poc.authorizationserver.security.interceptors;

import java.io.IOException;
import java.util.Map;

import org.apache.catalina.util.ParameterMap;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

public class CookieRefreshTokenExtractionFilter extends OncePerRequestFilter {
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {	
		String refreshTokenLocation = request.getParameter("COOKIE_REFRESH_TOKEN_FOR");
		
		if (isEndpointToExtract(request, refreshTokenLocation)) {
			for (Cookie cookie : request.getCookies()) {
				if (cookie.getName().equals("refreshToken")) {
					String refreshToken = cookie.getValue();
					request = new MyServletRequestWrapper(request, refreshToken, refreshTokenLocation);
				}
			}
		}
		filterChain.doFilter(request, response);
	}
	
	private boolean isEndpointToExtract(HttpServletRequest request, String refreshTokenLocation) {
		return request.getRequestURI().contains("/oauth2/") && refreshTokenLocation != null;
	}
	
	static class MyServletRequestWrapper extends HttpServletRequestWrapper {

		private final String refreshToken;
		private final String refreshTokenLocation;
		
		public MyServletRequestWrapper(HttpServletRequest request, String refreshToken, String refreshTokenLocation) {
			super(request);
			this.refreshToken = refreshToken;
			this.refreshTokenLocation = refreshTokenLocation;
		}
		
		@Override
		public Map<String, String[]> getParameterMap() {
			ParameterMap<String, String[]> map = new ParameterMap<>(getRequest().getParameterMap());
			map.put(refreshTokenLocation, new String[] { refreshToken });
			map.setLocked(true);
			return map;
		}
		
	}

}
