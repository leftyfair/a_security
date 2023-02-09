package com.jafa.exam;

import java.util.Locale;

import org.springframework.context.support.GenericXmlApplicationContext;

public class MessageExam {
	public static void main(String[] args) {
		GenericXmlApplicationContext ctx = new GenericXmlApplicationContext("classpath:appconfig.xml");
		String message_main = ctx.getMessage("main.greeting", new String[] {"조이", "파라다이스"}, Locale.getDefault());
		System.out.println(message_main);
	}
}
