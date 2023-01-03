package com.gdsc.jwtexample.controller;

import com.gdsc.jwtexample.domain.DTO.LoginDTO;
import com.gdsc.jwtexample.domain.DTO.TokenDTO;
import com.gdsc.jwtexample.service.MemberService;
import lombok.Getter;
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

    //login page
    @PostMapping("/login")
    public TokenDTO login(@RequestBody LoginDTO memberLoginRequestDto) {
        String memberId = memberLoginRequestDto.getMemberId();
        String password = memberLoginRequestDto.getPassword();
        TokenDTO tokenDTO = memberService.login(memberId, password);
        return tokenDTO;
    }

    //main page
    @GetMapping("/main")
    public ResponseEntity<String> main() {
        return ResponseEntity.ok("main");
    }

    //admin page
    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin");
    }

    //user page
    @GetMapping("/user")
    public ResponseEntity<String> user() {
        return ResponseEntity.ok("user");
    }
}