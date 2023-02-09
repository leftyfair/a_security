package com.jafa.repository;

import java.util.List;

import com.jafa.domain.MemberVO;

public interface MemberRepository {
	// 회원가입
	void save(MemberVO vo);
	
	// 로그인 체크 
	MemberVO read(String memberId);
	
	// 회원목록 
	List<MemberVO> memberList();
}
