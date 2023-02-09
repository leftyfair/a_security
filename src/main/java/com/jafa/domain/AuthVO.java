package com.jafa.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
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
