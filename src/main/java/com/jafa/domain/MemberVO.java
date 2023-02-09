package com.jafa.domain;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class MemberVO {
	private Long mno; 
	private String memberId; 
	private String password; 
	private String email;
	private boolean enabled;
	private List<AuthVO> authList;
}
