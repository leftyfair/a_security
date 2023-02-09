package com.jafa.repository;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.jafa.AppTest;

public class TestRepositoryTest extends AppTest {

	@Autowired
	TestRepository testRepository;
	
	@Test
	public void test() {
		System.out.println(testRepository.getCurrentDate());
	}

}
