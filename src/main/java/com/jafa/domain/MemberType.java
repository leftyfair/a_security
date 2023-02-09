package com.jafa.domain;

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