package com.gdsc.jwtpractice.controller;

import com.gdsc.jwtpractice.domain.DTO.LoginDTO;
import com.gdsc.jwtpractice.domain.DTO.TokenDTO;
import com.gdsc.jwtpractice.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    // 로그인, id와 pw가 저장된 request body를 자바 객체로 변환하고 로그인 과정에 사용
    @PostMapping("/login")
    // @RequestBody: HTTP Request Body 내용을 통째로 자바 객체로 변환해서 매핑된 메소드 파라미터로 전달
    public TokenDTO login(@RequestBody LoginDTO memberLoginRequestDto) {
        String memberId = memberLoginRequestDto.getMemberId();
        String password = memberLoginRequestDto.getPassword();
        TokenDTO tokenDTO = memberService.login(memberId, password);
        return tokenDTO;
    }

    // 메인 페이지
    @GetMapping("/index")
    public ResponseEntity<String> index() {
        return ResponseEntity.ok("main");
    }

    // 어드민 전용 페이지
    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin");
    }

    // 유저 전용 페이지
    @GetMapping("/user")
    public ResponseEntity<String> user() {
        return ResponseEntity.ok("user");
    }

    // 인증 테스트 페이지, 따로 지정하지 않은 uri -> 인증(로그인)만 필요
    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("test");
    }
}