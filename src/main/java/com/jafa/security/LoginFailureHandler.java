package com.jafa.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
public class LoginFailureHandler implements AuthenticationFailureHandler  {

	private String errorMessage; // 에러 메세지

	@Value("/member/login")
	private String defaultFailureUrl; // 로그인 실패시 이동할 URL 
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		String loginId = request.getParameter("loginId");
		
		if(exception instanceof BadCredentialsException) {
			errorMessage = "아이디 또는 비밀번호가 일치하지 않음";
		}else if(exception instanceof InternalAuthenticationServiceException) {
			errorMessage = "아이디 또는 비밀번호가 일치하지 않음";
        } else if(exception instanceof DisabledException) {
        	errorMessage = "계정이 비활성화되었습니다. 관리자에게 문의하세요.";
        } else if(exception instanceof CredentialsExpiredException) {
        	errorMessage = "비밀번호 유효기간이 만료 되었습니다.관리자에게 문의하세요.";
        } else {
        	errorMessage = "알수 없는 오류";
        }
		request.setAttribute("errorMessage", errorMessage);
		request.setAttribute("loginId", loginId);
		request.getRequestDispatcher(defaultFailureUrl).forward(request, response);
	}
}
