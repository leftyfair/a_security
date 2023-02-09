package com.jafa.repository;

import com.jafa.domain.AuthVO;

public interface AuthRepository {
	// 회원등급
	void save(AuthVO vo);
	
	void remove(String memberId);
}