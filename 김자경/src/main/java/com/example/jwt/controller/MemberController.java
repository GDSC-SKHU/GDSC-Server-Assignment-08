package com.example.jwt.controller;

import com.example.jwt.domain.DTO.LoginDTO;
import com.example.jwt.domain.DTO.TokenDTO;
import com.example.jwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    // 로그인 페이지
    @PostMapping("/login")
    public TokenDTO login(@RequestBody LoginDTO memberLoginRequestDto) {
        String memberId = memberLoginRequestDto.getMemberId(); // 아이디
        String password = memberLoginRequestDto.getPassword(); // 비밀번호
        TokenDTO tokenDTO = memberService.login(memberId, password);
        return tokenDTO;
    }

    // 관리자 페이지 -> 전체 관리 권한의 접근 권한 관리
    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin");
    }

    // 사용자 페이지
    @GetMapping("/user")
    public ResponseEntity<String> user() { return ResponseEntity.ok("user"); }
}