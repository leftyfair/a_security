# XML기반 시큐리티 설정 

## 디펜던시 추가 
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-core</artifactId>
    <version>5.1.5.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>5.1.5.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-web</artifactId>
    <version>5.1.5.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-taglibs</artifactId>
    <version>5.1.5.RELEASE</version>
</dependency>
```

## security-context.xml 생성 
- 네임스페이스에서 security 항목 체크하고 버전정보를 없앤다. 

## web.xml 설정
- 스프링시큐리티가 MVC동작에 관여하려면 필터를 설정하여한다. 
- DelegatingFilterProxy 필터를 등록한다. 
```xml 
<filter>
	<filter-name>springSecurityFilterChain</filter-name>
	<filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
	<filter-name>springSecurityFilterChain</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>
```

- security-context.xml 설정정보를 컨텍스트 파라미터로 전달한다. 
- 컨텍스트 파라미터의 param-value태그는 여러개의 값을 설정할 수 있다. 
- 줄바꿈으로 각각의 파라미터값이 구분된다. 
```xml
<!-- 스프링 시큐리티 설정파일 전달 -->
<context-param>
	<param-name>contextConfigLocation</param-name>
	<param-value>
		classpath:spring-config/root-context.xml
		classpath:spring-config/security-context.xml
	</param-value>
</context-param>
```

- 프로젝트를 실행하면 springSecurityFilterChain을 스프링 필터로 등록할 수 없다는 메시지가 표시된다. 
- 시큐리티가 동작하기 위해서는 secruity-context.xml에서 최소한의 설정을 해주어야 한다. 
```xml
<security:http>

	<security:form-login/>	
	
</security:http>

<security:authentication-manager>
	
</security:authentication-manager>
```

<br>

## 스프링시큐리티 동작을 테스트할 컨트롤러 생성 
    각 요청에 해당하는 VIEW 페이지를 생성한다. 
```JAVA
@Log4j
@Controller
@RequestMapping("/member")
public class SecurityExamController {
	
	@GetMapping("/all")
	public void doAll() {
		log.info("모두 접근 허용");
	}
	
	@GetMapping("/member")
	public void doMember() {
		log.info("로그인한 사용자만 접근 가능");
	}
	
	@GetMapping("/admin")
	public void doAdmin() {
		log.info("관리자만 접근가능");
	}
}
```

<br>

## 접근 제한 설정 
```XML
<!-- 접근제한 설정 -->
<security:http>
    <security:intercept-url pattern="/member/all" access="permitAll"/>
    <security:intercept-url pattern="/member/member" access="hasRole('ROLE_MEMBER')"/>
    <security:intercept-url pattern="/member/admin" access="hasRole('ROLE_ADMIN')"/>
</security:http>
``` 
    pattern 속성 : 스프링시큐리티가 관여할 url패턴
    access 속성 : 권한 체크, 표현식과 문자열 사용가능 위의 설정은 표현식이 사용됨 

```xml 
<!-- access속성에 문자열 사용 예시 -->
<security:http auto-config="true" use-expressions="true">
    <security:intercept-url pattern="/member/member" access="ROLE_MEMBER"/>
</security:http>
```

    member/member로 요청하면 시큐리티가 제공하는 기본 로그인 폼으로 이동한다. 

<br>

## 인증과 권한에 관한 처리 
    인증에 관한처리는 AuthenticationProvider타입의 객체가 처리함
    인증된 정보에 전달된 권한정보의 처리를 UserDetailService타입의 객체가 처리함
    다음은 설정의 예이다. 
```xml
<security:authentication-manager>
    <!-- 인증과 권한에 대한 처리 -->
    <security:authentication-provider>
        <security:user-service>
            <security:user name="leekwanghyup" password="1234" authorities="ROLE_MEMBER"/>
            <security:user name="admin" password="2244" authorities="ROLE_ADMIN"/>			
        </security:user-service>		
    </security:authentication-provider>
</security:authentication-manager>
```
    프로젝트를 실행하고 로그인을 요청하면 다음과 같은 에러가 발생한다. 
    There is no PasswordEncoder mapped for the id "null"
    이 에러는 PasswordEncoder가 없기 때문에 발생한다. 
    패스워드의 인코딩 처리 없이 사용할 경우 다음과 같이 설정한다. 
```xml
<security:user name="leekwanghyup" password="{noop}1234" authorities="ROLE_MEMBER"/>
```

<br>

## 여러개의 권한을 가진 사용자 
    일반적으로 관리자 계정은 MEMBER권한과 ADMIN권한 모두 가져야한다. 
    authorities 속성에서 ','로 구분하여 여러개의 권한을 가지게 할 수 있다. 
```xml
<security:user name="admin" password="{noop}2244" authorities="ROLE_ADMIN, ROLE_MEMBER"/>
```
    
<br>

## 접근제한 처리 : 특정 URL 요청
    로그인을 성공하였음에도 권한이 없는 경우 403페이지를 표시하게 된다. 
    스프링시큐리티는 특정페이지를 이동하게하거나 AccessDeniedHandelr인터페이스를 구현하여 접근제한에 대한 처리를 할 수 있다. 
    접근제한의 경우에 대하여 특정한 URL 요청하는 경우의 설정의 예이다. 
    
```xml
<security:http>
    <!-- 나머지 코드 생략 -->
    <security:access-denied-handler error-page="/accessError"/>
</security:http>
```
    error-page속성으로 요청할 URL을 지정하였다. 루트경로는 컨텍스트 패스를 포함한다. 
    해당 요청을 받는 컨트롤러 메서드를 생성한다. 

```java
@Controller
@RequestMapping("/member")
public class SecurityExamController {

    // 나머지 코드 생략...

	//권한이 없는 경우 이동할 페이지 지정 
	@GetMapping("/accessError")
	public void accessError() {
		System.out.println("접근이 거부되었습니다. 관리자에게 문의하십시오.");
	}
}
```

<br>

## 접근제한 처리 핸들러 
    접근제한의 경우 쿠키나 세션에 특정한 작업업을 하거나 헤더 정보를 추가하는 등의 다양한 작업이 필요한 경우 
```java
// 권한이 없을 경우 작업 수행 
public class MemberAccessDeniedHanlder implements AccessDeniedHandler{
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		System.out.println("AccessDeniedHandler 동작 ");
		response.sendRedirect(request.getContextPath()+"/member/accessError");
	}
}
```

    AccessDeniedHandler 구현체 생성 후 설정파일에 스프링빈으로 등록해야한다. 
    또한 ref 속성을 사용하여 해당 스프링빈을 참조할 수 있게 한다. 

```xml
<!-- AccessDeniedHanlder빈 등록 -->
<bean id="memberAccessDeniedHanlder" class="com.jafa.security.MemberAccessDeniedHanlder"/>
<!-- AccessDeniedHanlder 인터페이스 구현 -->
<security:access-denied-handler ref="memberAccessDeniedHanlder"/>
```

## 로그인 페이지 생성 
    login-page속성에 특정 URL을 지정하여 로그인 페이지를 직접 생성할 수 있다. 
	login-processing-url : 로그인 처리 URL, 기본값 : /login
	username-parameter : 로그인 페이지의 회원아이디 name속성 지정, 기본값-username
	password-parameter : 로그인 페이지의 회원비밀번호 name속성 지정, 기본값-password
	default-target-url : 로그인 성공 후 요청URL, 기본값 : /
	
```xml
<security:form-login login-page="/member/loginForm"/>
```
```java
@Controller
@RequestMapping("/member")
public class SecurityExamController {
    // 나머지 코드 생략 

	// 커스텀 로그인 페이지로 이동 
	@GetMapping("/loginForm")
	public String loginForm() {
		return "member/login";
	}    
}
```
    별도의 설정이 없다면 
    로그인을 처리하는 경로는 POST 방식의 '/loing'으로 정해져있다. 
    로그인 아이디의 비밀번호 name속성은 각각 username, password로 지정되어있다. 

```html
<div class="container">
	<div class="jumbotron">
		<h2>회원 로그인</h2>
	</div>
	<form action="${contextPath}/login" method="post">
		<div class="form-group">
			<label>아이디: </label>
			<input type="text" name="username" class="form-control">
		</div>
		<div class="form-group">
			<label>비밀번호 : </label>
			<input type="text" name="password" class="form-control">
		</div>
		<button class="btn btn-primary">로그인</button>
		<!-- csrf 토큰 -->
		 <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
	</form>
</div>
```

<br>

## 로그인 실패 핸들러  
	접근제한과 마찬가지로 로그인 실패시에도 특정한 URL을 요청하게 할 수 있다. 
	authentication-failure-url 속성 사용 
```xml 
	<security:form-login login-page="/member/loginForm" authentication-failure-url="/loginFail"/>
```

	AuthenticationFailureHandler인터페이스를 구현하여  로그인 실패시 부가적인 처리를 할 수 있음 

```java
@Getter
@Setter
public class LoginFailureHandler implements AuthenticationFailureHandler  {

	private String errorMessage; // 에러 메세지
	private String defaultFailureUrl; // 로그인 실패시 이동할 URL 
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		String username = request.getParameter("username");
		
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
		request.setAttribute("username", username);
		request.getRequestDispatcher(defaultFailureUrl).forward(request, response);
	}
}
```
	AuthenticationFailureHandler 객체를 스프링빈으로 등록 
	로그인에 실패하면 이 빈을 참조하도록 함 
	authentication-failure-handler-ref 속성에서 해당 빈 지정 
```xml
<!--security-xml 설정-->
<!-- AuthenticationFailureHandler 스프링빈 등록 -->
<bean id="loginFailureHandler" class="com.jafa.security.LoginFailureHandler">
	<property name="defaultFailureUrl" value="/member/loginForm?error"/>
</bean>


<!-- 로그인 실패 핸들러 지정 -->		
<security:form-login login-page="/member/loginForm"
	authentication-failure-handler-ref="loginFailureHandler"/>
```

	컨트롤러에서 로그인 실패시 보낼 데이터를 지정해야함 
```java
	// 로그인 페이지  
	@RequestMapping("/loginForm") // @RequestMapping 변경 
	public String loginForm(HttpServletRequest request, Model model) {
		if(request.getParameter("errorMessage")!=null) { // 로그인 실패시 처리 
			model.addAttribute("errorMessage", request.getParameter("errorMessage"));
			model.addAttribute("username", request.getParameter("username"));
		}
		return "member/login";
	}
```

	로그인 페이지 
```html
<!-- 로그인 실패시 아이디 기억-->
<input type="text" name="username" class="form-control" value="${username }">


<!-- 로그인 실패시 보일 메세지  -->
<c:if test="${not empty errorMessage}">
<div class="alert alert-danger">
	<strong>${errorMessage}</strong>
</div>
</c:if>
```

<br>

## 로그인 성공 처리 핸들러
	AuthenticationSuccessHandler 인터페이스를 구현하여 로그인 성공식 부가적인 작업 처리 
```java
// 로그인 성공시 부가적인 작업 수행
public class LoginSuccessHandler implements AuthenticationSuccessHandler{

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication auth) throws IOException, ServletException {
		System.out.println(auth.getAuthorities()); // 회원등급
		System.out.println(request.getRequestURL()); // 요청주소
		System.out.println(auth.getName()); // 회원아이디s
		response.sendRedirect(request.getContextPath()+ "/");
	}
}
```
	
```xml
<!-- AccessDeniedHanlder빈 등록 -->
<bean id="memberAccessDeniedHanlder" class="com.jafa.security.MemberAccessDeniedHanlder"/>


<!-- 로그인 성공 핸들러 지정 -->		
<security:form-login login-page="/member/loginForm"
	authentication-failure-handler-ref="loginFailureHandler"
	authentication-success-handler-ref="loginSuccessHandler"/>
```

<br>

## 로그아웃 처리 

```html 
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

<div class="container">
	<h1>메인</h1>
	<sec:authorize access="isAnonymous()"><!-- 권한이 없는 경우  -->
		<a href="${contextPath}/member/loginForm">로그인</a>
	</sec:authorize>
	<sec:authorize access="isAuthenticated()"> <!-- 권한이 있는 경우  -->
		<p>로그인 중 : <sec:authentication property="principal.username"/></p> <!-- 로그인 id-->
		<form action="${contextPath}/logout" method="post"> <!-- 기본값 : /logout -->
			<!-- post 전송 방식은 csrf토큰이 필요함-->
			<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
			<button class="btn btn-primary">로그아웃</button>
		</form> 
	</sec:authorize>
	<div>
		<a href="${contextPath}/member/all">/member/all</a><br>
		<a href="${contextPath}/member/member">/member/member</a><br>
		<a href="${contextPath}/member/admin">/member/admin</a><br>
	</div>
</div>
```
	logout-url : 로그아웃 요청 주소, 기본값은 - /logout
	logout-success-url : 로그아웃 성공시 요청 주소, 기본값 - 로그인 페이지
```xml
<!-- 로그아웃 security:http 하위 태그-->
<security:logout invalidate-session="true"/>
```

<br>

## 로그아웃 성공 처리 핸들러 
	LogoutSuccessHandler 인터페이스 구현 
```java
public class LogoutSuccesHandlerImpl implements LogoutSuccessHandler{

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth)
			throws IOException, ServletException {
		// 로그아웃 성공시 부가적인 작업 처리
		// ex) 마지막 로그아웃 시간 기록 
		System.out.println(auth.getName()+" 로그아웃");
		response.sendRedirect(request.getContextPath());
	}
}
```xml
<!-- 로그아웃 -->
<security:logout invalidate-session="true"
		success-handler-ref="logoutSuccesHandler"/>		

<!-- LogoutSuccesHandler빈 등록  -->
<bean id="logoutSuccesHandler" class="com.jafa.security.LogoutSuccesHandlerImpl"/>
```

## JDBC를 이용한 인증/권한 처리를 위한 테이블 

	회원 테이블 생성 
	권한 테이블 생성 
```sql
drop table member_auth;
drop table member_sec01; 
drop sequence member_sec01_seq;

-- 회원 테이블
create sequence member_sec01_seq;
create table member_sec01(
    mno number(10) primary key, 
    memberId varchar2(50) unique not null,
    password varchar2(200)not null, 
    email varchar2(200), 
    enabled char(1) default(1)
);

-- 권한 테이블
create table member_auth(
    memberId varchar2(50) not null, 
    memberType varchar2(50) not null, 
	ordinal number(10) not null,
    constraint fk_member_auth foreign key(memberId)
    references member_sec01(memberId)
);

select * from member_sec01;
select * from member_auth;
```

<br>

## 회원가입 처리 
	
### 회원 도메인 
```java
public enum MemberType {
	
	ROLE_ADMIN("관리자"), 
	ROLE_SUB_ADMIN("부관리자"), 
	ROLE_REGULAR_MEMBER("정회원"),
	ROLE_ASSOCIATE_MEMBER("준회원");

	private final String name; 

	MemberType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
}

@ToString
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthVO {
	private String memberId; 
	private MemberType memberType;
	private int ordinal;
	
	public AuthVO(String memberId, MemberType memberType) {
		this.memberId = memberId;
		this.memberType = memberType;
	}
}

@ToString
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class MemberVO {
	private Long mno; 
	private String memberId; 
	private String password; 
	private String email;
	private boolean enalbed;	
	private List<AuthVO> authList;
}
```

<br>

### 회원가입 처리 관련 자바 코드 : Repository, Service, Controller
```java
// Repository
public interface MemberRepository {
	// 회원가입
	void save(MemberVO vo);
}

public interface AuthRepository {
	// 회원등급
	void save(AuthVO vo);
}

// Service
@Service
public class MemberService {

	@Autowired
	MemberRepository memberRepository;
	
	@Autowired
	AuthRepository authRepository; 
	
	// 회원가입
	@Transactional
	public void join(MemberVO vo) {
		memberRepository.save(vo);
		AuthVO authVO = AuthVO.builder()
				.memberId(vo.getMemberId())
				.memberType(MemberType.ROLE_ASSOCIATE_MEMBER)
				.ordinal(MemberType.ROLE_ASSOCIATE_MEMBER.ordinal())
				.build();
		authRepository.save(authVO);
	}
}

// Controller
@Log4j
@Controller
@RequestMapping("/member")
public class SecurityExamController {
	
	@Autowired
	MemberService memberService; 

	// ... 나머지 코드 생략 ...

	// 회원가입폼
	@GetMapping("/join")
	public void joinForm() {
		
	}
	
	//회원가입처리
	@PostMapping("/join")
	public String join(MemberVO vo, RedirectAttributes rttr) {
		memberService.join(vo);
		return "redirect:/";
	}
}
```

<br>

### 회원가입 매퍼 
```xml
<mapper namespace="com.jafa.repository.MemberRepository">
	<insert id="save">
		insert into member_sec01(mno, memberId, password, email)
		values(member_sec01_seq.nextval,#{memberId}, #{password}, #{email})
	</insert>
</mapper>

<mapper namespace="com.jafa.repository.AuthRepository">
	<insert id="save">
		insert into member_auth(memberId,memberType,ordinal)
		values(#{memberId}, #{memberType},#{ordinal})
	</insert>
</mapper>

```

### 회원가입 매퍼 테스트 
```java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
		"classpath:spring-config/root-context.xml",
		"classpath:spring-config/servlet-context.xml",
		"classpath:spring-config/security-context.xml",
})
@WebAppConfiguration
public class MemberJoinTest {
	
	@Autowired
	MemberRepository memberRepository;
	
	@Autowired
	AuthRepository authRepository;
	
	@Test
	public void test() {
		MemberVO vo = MemberVO.builder()
				.memberId("leekwanghyup")
				.password("1234")
				.email("lee@naver.com")
				.build();
		memberRepository.save(vo);
		AuthVO authVO = AuthVO.builder()
				.memberId(vo.getMemberId())
				.memberType(MemberType.ROLE_ASSOCIATE_MEMBER)
				.ordinal(MemberType.ROLE_ASSOCIATE_MEMBER.ordinal())
				.build();
		authRepository.save(authVO);
	}
}
```

### 회원가입 페이지 
	
```html
<!-- 회원가입 페이지로 이동 index.jsp -->
<sec:authorize access="isAnonymous()">
	<a href="${contextPath}/member/join">회원가입</a><br>
	<a href="${contextPath}/member/loginForm">로그인</a>
</sec:authorize>
```

<br>

```html
<div class="container">
	<div class="jumbotron">
		<h1>회원 가입</h1>
	</div>
	<form action="${contextPath}/member/join" method="post">
		<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
		<div class="form-group">
			<input type="text" name="memberId" class="form-control" placeholder="아이디">
		</div>
		<div class="form-group">
			<input type="text" name="password" class="form-control" placeholder="비밀번호">
		</div>
		<div class="form-group">
			<input type="text" name="email" class="form-control" placeholder="이메일">
		</div>
		<button class="btn btn-primary">가입하기</button>
	</form>
</div>
```

## 비밀번호 암호화 

	security-context.xml
```xml
<!-- 비밀번호 암호화 빈등록 -->
<bean id="bCryptPasswordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
```

<br>

```java
@Service
public class MemberService {

	// 생략 ....
	
	// 비밀번호 암호화 
	@Autowired
	BCryptPasswordEncoder passwordEncoder;
	
	
	@Transactional
	public void join(MemberVO vo) {

		// 생략 ....
		vo.setPassword(passwordEncoder.encode(vo.getPassword())); // 비밀번호 암호화 

	}
}
```

## JDBC 인증/권한 처리 

### 회원 로그인 매퍼 
```java
public interface MemberRepository {	
	// 로그인 체크 
	MemberVO read(String memberId);
}
```

```xml
<!-- 회원로그인정보 -->
<select id="read" resultMap="memberMap">
	SELECT * FROM member_sec01 WHERE memberId = #{memberId}
</select>
<resultMap type="com.jafa.domain.MemberVO" id="memberMap">
	<result property="mno" column="mno"/>
	<result property="memberId" column="memberId"/>
	<result property="password" column="password"/>
	<result property="email" column="email"/>
	<result property="enabled" column="enabled"/>
	<collection property="authList" 
		column="memberId" 
		javaType="java.util.ArrayList" 
		ofType="com.jafa.domain.AuthVO"
		select="getAuthList"/>
</resultMap>
<select id="getAuthList" resultType="com.jafa.domain.AuthVO">
	select * from member_auth where memberId=#{memberId} order by ordinal
</select>
```

### 매퍼테스트 
```java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
		"classpath:spring-config/root-context.xml",
		"classpath:spring-config/servlet-context.xml",
		"classpath:spring-config/security-context.xml",
})
@Log4j
public class MemberRepositoryTest {

	@Autowired
	MemberRepository memberRepository;
		
	@Test
	public void test() {
		MemberVO read = memberRepository.read("leekwanghyup");
		log.info(read);
	}
}
```

## UserDetailService 사용

### MemberDetail
	org.springframework.security.core.userdetails.User 상속 
	스프링 시큐리티에서 MemberVO객체를 사용하기 위해 User타입으로 래핑함
	권한정보를 SimpleGrantedAuthority객체로 래핑함 
```java
// 도메인에 정의 
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;


@Getter
public class MemberDetail extends User {

	MemberVO memberVO; 
	
	public MemberDetail(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	public MemberDetail(MemberVO vo) {
		super(vo.getMemberId(), vo.getPassword(),
				vo.getAuthList().stream()
				.map(auth-> new SimpleGrantedAuthority(auth.getMemberType().toString()))
				.collect(Collectors.toList()));
		this.memberVO = vo;
	}
}
```

<br>

### CustomUserDetailService
	UserDetailsService 인터페이스 구현
	매퍼에서 회원정보를 조회하여 MemberVO객체를 받아옴
	MemberVO를 MemberDetail(User타입)객체로 래핑하여 반환
	회원아이디를 찾지 못할 경우 UsernameNotFoundException예외를 발생시켜야함 
	UsernameNotFoundException예외처리는 시큐리티에서 자동처리함 
	시큐리티 설정파일에 스프링빈으로 등록해야함.
```java
// 서비스에 정의 
public class CustomUserDetailService implements UserDetailsService{
	
	@Autowired
	private MemberRepository memberRepository;
	
	@Override
	public UserDetails loadUserByUsername(String memberId) throws UsernameNotFoundException {
		MemberVO vo = memberRepository.read(memberId);
		if(vo==null) {
			throw new UsernameNotFoundException("not found member");
		}
		return new MemberDetail(vo);
	}
}
```

<br>

### 시큐리티 설정 파일
```xml
<!-- CustomUserDetailsService 빈 등록 -->
<bean id="customUserDetailService" class="com.jafa.service.CustomUserDetailService"/>

<!-- 나머지 코드 생략 ... -->

<security:authentication-manager>
	<!-- 인증과 권한에 대한 처리 -->
	<security:authentication-provider user-service-ref="customUserDetailService">
		<security:password-encoder ref="bCryptPasswordEncoder"/>
	</security:authentication-provider>
</security:authentication-manager>
```

## 회원 등급 변경 

```java
// Repository 
public interface AuthRepository {
	// 회원등급
	void save(AuthVO vo);
	
	// 모든 회원등급 삭제
	void remove(String memberId);
}


// Service
@Service
public class MemberService {

	// 나머지 코드 생략 ...

	// 회원 등급변경 
	@Transactional
	public void updateMemberType(AuthVO authVO) {
		authRepository.remove(authVO.getMemberId()); // 모든등급삭제 
		MemberType memberType = authVO.getMemberType(); // 변경할 회원등급 
		MemberType[] types = MemberType.values(); // 전체 회원등급
		for(int i=memberType.ordinal(); i<types.length;i++) {
			AuthVO vo = AuthVO.builder()
				.memberId(authVO.getMemberId())
				.memberType(types[i])
				.ordinal(types[i].ordinal())
				.build();
			authRepository.save(vo);
		}
	}
}
```
```xml
<delete id="remove">
	delete from member_auth where memberId=#{memberId}
</delete>

```

<br>

### 테스트 코드 

```java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
		"classpath:spring-config/root-context.xml",
		"classpath:spring-config/servlet-context.xml",
		"classpath:spring-config/security-context.xml",
})
@Log4j
public class MemberServiceTest {
	
	@Autowired
	MemberService memberService;

	@Test
	@Ignore
	public void test() {
		AuthVO auth = new AuthVO("admin", MemberType.ROLE_ADMIN);
		memberService.updateMemberType(auth);
	}
	
	@Test
	public void test2() {
		AuthVO auth = new AuthVO("leekwanghyup", MemberType.ROLE_REGULAR_MEMBER);
		memberService.updateMemberType(auth);
	}
}
```

### 관리자 페이지에서  회원 목록 조회 및 권한 변경 

```java
@Controller
@RequestMapping("/member")
public class SecurityExamController {
	
	// ...
	
	// 관리자 페이지에서 회원목록 조회 
	@GetMapping("/admin")
	public void doAdmin(Model model) {
		log.info("관리자만 접근가능");
		List<MemberVO> memberList = memberService.memberList();
		model.addAttribute("list", memberList);
		model.addAttribute("mType", MemberType.values());
	}
}


@Service
public class MemberService {

	// ... 

	// 회원목록 조회 
	public List<MemberVO> memberList(){
		return memberRepository.memberList();
	}
}

public interface MemberRepository {

	// ....
	
	// 회원목록 
	List<MemberVO> memberList();
}
```
```xml
<mapper namespace="com.jafa.repository.MemberRepository">

	<!-- ... -->

	<!-- 관라자페이지에서 회원목록 조회-->
	<select id="memberList" resultMap="memberMap">
		select * from member_sec01
	</select>

</mapper>
```

```java
@Getter
@Setter
@ToString
public class AuthListDTO {
	private List<AuthVO> authList; 
}

@Controller
@RequestMapping("/member")
public class SecurityExamController {

	// ...

	// 회원등급변경 
	@PostMapping("/upadteMemberType")
	public String updateMemberType(AuthListDTO authListDTO, RedirectAttributes rttr) {
		log.info(authListDTO.getAuthList());
		List<AuthVO> authList = authListDTO.getAuthList();
		for(AuthVO vo : authList) {
			if(vo.getMemberId()!=null&&vo.getMemberType()!=null){
				memberService.updateMemberType(vo);
			}
		}
		rttr.addFlashAttribute("updateMember", "등급변경");
		return "redirect:/member/admin";
	}
}
```

```html
<!--  admin.jsp 페이지-->
<div class="container">
	<div class="jumbotron">
		<h1>관리자 페이지</h1>
	</div>
	
	<form action="${contextPath}/member/upadteMemberType" method="post">
	<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
	<table class="table">
		<tr>
			<th>회원번호</th>
			<th>아이디</th>
			<th>이메일</th>
			<th>회원등급</th>
			<th>상태</th>
		</tr>
		<c:forEach var="m" items="${list}" varStatus="mst">
		<c:if test="${m.authList[0].memberType != mType[0]}">
		<tr>
			<td>${m.mno }</td>
			<td>${m.memberId }
				<input type="hidden" name="authList[${mst.index}].memberId" value="${m.memberId}">
			</td>
			<td>${m.email }</td>
			<td>
				<select name="authList[${mst.index}].memberType">
				<c:forEach items="${mType}" var="type" varStatus="st">
					<option value="${type}" ${m.authList[0].memberType==type ? 'selected':''}>${type.name}</option>
				</c:forEach>
				</select>
			</td>
			<td>${m.enabled ? '활성':'비활성' }</td>
		</tr>
		</c:if>
		</c:forEach>
		
	</table>
	<button>전송</button>
	</form>
</div>

```

### 스프링 시큐리티 표현식 

- hasRole : 해당 권한이 있을 때 
```html
<sec:authorize access="hasRole('ROLE_ADMIN')">
	<a href="${contextPath}/member/admin">관리자페이지</a><br>
</sec:authorize>
```

- hasAnyRole : 여러 권한 중에서 어느 하나 가 있을 때 
```xml
<!-- 스프링 설정 파일 -->
<security:intercept-url pattern="/member/admin" access="hasAnyRole('ROLE_ADMIN', 'ROLE_SUB_ADMIN')" />
<security:intercept-url pattern="/member/myPage" access="hasAnyRole('ROLE_REGULAR_MEMBER', 'ROLE_ASSOCIATE_MEMBER')" />
```

```html
<sec:authorize access="hasAnyRole('ROLE_ADMIN','ROLE_SUB_ADMIN')">
	<a href="${contextPath}/member/admin">관리자페이지</a><br>
</sec:authorize>
```



### MyPage 구현 
```java
// 컨트롤러 
@Controller
@RequestMapping("/member")
public class SecurityExamController {

	// Authentication : 인증된 사용자의정보가 담겨 있는 객체 
	@GetMapping("/mypage")
	public String myPage(Authentication  auth, Model model) {
		log.info("로그인한 사용자만 접근 가능");
		MemberDetail principal = (MemberDetail) auth.getPrincipal();
		MemberVO memberVO = principal.getMemberVO();
		model.addAttribute("memberInfo", memberVO);
		return "member/mypage";
	}

	// ...
}

// 서비스 
@Service
public class MemberService {

	// 나머지 코드 ...

	// 회원정보 조회 
	public MemberVO memberInfo(String memberId) {
		return memberRepository.read(memberId);
	}

}
```

```html
<!-- index.jsp -->
<sec:authorize access="hasRole('ROLE_REGULAR_MEMBER')">
	<a href="${contextPath}/member/mypage">나의 정보보기</a><br>
</sec:authorize>


<!-- mypage.jsp 생략 ... -->
```



## Remember-me 
```sql
create table persistent_logins (
	username varchar(64) not null,
	series varchar(64) primary key,
	token varchar(64) not null,
	last_used timestamp not null
);
```
```xml
<!-- 로그인 상태 유지 -->		
<security:remember-me data-source-ref="dataSource" token-validity-seconds="604800"/>

<!-- 로그아웃 -->
<security:logout invalidate-session="true"
		delete-cookies="remember-me,JSESSION_ID"
		success-handler-ref="logoutSuccesHandler"/>
```
```html
<button class="btn btn-primary">로그인</button>
<input type="checkbox" name="remember-me"> 로그인 상태 유지
```

