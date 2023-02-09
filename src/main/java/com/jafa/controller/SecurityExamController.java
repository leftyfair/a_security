package com.jafa.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.jafa.domain.MemberType;
import com.jafa.domain.MemberVO;
import com.jafa.service.MemberService;

import lombok.extern.log4j.Log4j;

@Log4j
@Controller
@RequestMapping("/member")
public class SecurityExamController {

	@Autowired
	MemberService memberService; 
	
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
	
	@GetMapping("/accessError")
	public void accessError() {
		log.info("접근이 거부됨.");
		// member/accessError.jsp 생성
	}
	
	@RequestMapping("/login")
	public void login() {
		log.info("로그인 페이지");
	}
	
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
	
	@GetMapping("/admin")
	public void doAdmin(Model model) {
		log.info("관리자만 접근가능");
		List<MemberVO> memberList = memberService.memberList();
		model.addAttribute("list", memberList);
		model.addAttribute("mType", MemberType.values());
	}
	
}
