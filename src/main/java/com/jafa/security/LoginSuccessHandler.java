package com.jafa.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler{

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication auth) throws IOException, ServletException {
		System.out.println(auth.getAuthorities()); // 회원등급
		System.out.println(request.getRequestURL()); // 요청주소
		System.out.println(auth.getName()); // 회원아이디
		response.sendRedirect(request.getContextPath()+ "/");
	}
}