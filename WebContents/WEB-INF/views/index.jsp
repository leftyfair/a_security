<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ include file="layout/header.jsp" %>

<div class="container">
	<h1>메인</h1>
	<sec:authorize access="isAnonymous()"><!-- 권한이 없는 경우  -->
		<a href="${contextPath}/member/join">회원가입</a><br>
		<a href="${contextPath}/member/login">로그인</a><br>
	</sec:authorize>
	<sec:authorize access="isAuthenticated()"> <!-- 권한이 있는 경우  -->
		<p>로그인 중 : <sec:authentication property="principal.username"/></p> <!-- 로그인 id-->
		<form action="${contextPath}/member/logout" method="post"> <!-- 기본값 : /logout -->
			<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
			<button class="btn btn-primary">로그아웃</button>
		</form> 
	</sec:authorize>
	<a href="${contextPath}/member/all">모든 사용자 접근 가능</a><br>
	<a href="${contextPath}/member/member">로그인한 사용자만 접근 가능</a><br>
	<a href="${contextPath}/member/admin">관리자만 접근 가능</a>	<br>
</div>

<%@ include file="layout/footer.jsp" %>
