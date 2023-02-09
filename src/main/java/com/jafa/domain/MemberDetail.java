package com.jafa.domain;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import lombok.Getter;

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
