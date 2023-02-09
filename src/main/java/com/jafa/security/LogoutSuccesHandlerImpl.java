package com.jafa.security;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import lombok.extern.log4j.Log4j;

@Log4j
@Component
public class LogoutSuccesHandlerImpl implements LogoutSuccessHandler{

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth)
			throws IOException, ServletException {
		// 로그아웃 성공시 부가적인 작업 처리
		// ex) 마지막 로그아웃 시간 기록 
		log.info(auth.getName()+" 로그아웃");
		response.sendRedirect(request.getContextPath());
	}
}
