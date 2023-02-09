<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>

<%@ include file="../layout/header.jsp" %>

<div class="container">
	<div class="jumbotron bg-warning">
		<h1>관리자페이지</h1>
	</div>
	<form action="${contextPath}/member/updateMemberType" method="post">
		<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
		<table class="table">
			<tr>
				<th>회원번호</th>
				<th>아이디</th>
				<th>이메일</th>
				<th>회원등급</th>
				<th>회원상태</th>
			</tr>
		
			<c:forEach items="${list}" var="m" varStatus="mst">
				<c:if test="${m.authList[0].memberType != mType[0]}"> <!-- ADMIN등급을 표시하지 않음 -->
					<tr>
						<td>${m.mno}</td>			
						<td>${m.memberId}
							<input type="hidden" name="authList[${mst.index}].memberId" value="${m.memberId}">
						</td>			
						<td>${m.email}</td>			
						<td>
							<select name="authList[${mst.index}].memberType">
								<c:forEach items="${mType}" var="type">
									<option value="${type}" ${m.authList[0].memberType == type ? 'selected' : ''} >${type.name}</option>
								</c:forEach>
							</select>
						</td>			
						<td>${m.enabled}</td>			
					</tr>
				</c:if>
			</c:forEach>
		</table>
		<button class="btn btn-primary">등급변경</button>
	</form>
</div>

<%@ include file="../layout/footer.jsp" %>

<script>
let updateMember = "${updateMember}";
if(updateMember != '') alert(updateMember);
</script>
