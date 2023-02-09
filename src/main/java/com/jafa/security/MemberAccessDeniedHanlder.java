package com.jafa.security;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import lombok.extern.log4j.Log4j;

@Log4j
@Component
public class MemberAccessDeniedHanlder implements AccessDeniedHandler{

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		log.info("AccessDeniedHandler 동작 ");
		response.sendRedirect(request.getContextPath()+"/member/accessError");
	}
}
