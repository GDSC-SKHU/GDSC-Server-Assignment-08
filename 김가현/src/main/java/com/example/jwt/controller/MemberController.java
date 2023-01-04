package com.example.jwt.controller;

import com.example.jwt.domain.DTO.LoginDTO;
import com.example.jwt.domain.DTO.TokenDTO;
import com.example.jwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/login") //로그인 컨트롤러
    @RequestMapping(value="/login", method = {RequestMethod.GET}) //Request method 'GET' not supported 해결용
    public TokenDTO login(@RequestBody LoginDTO memberLoginRequestDto) {
        String memberId = memberLoginRequestDto.getMemberId();
        String password = memberLoginRequestDto.getPassword();
        TokenDTO tokenDTO = memberService.login(memberId, password);
        return tokenDTO;
    }


    @GetMapping("/index") //메인 컨트롤러, 메인 페이지
    public ResponseEntity<String> index() {
        return ResponseEntity.ok("main page");
    }

    @GetMapping("/admin") //어드민 컨트롤러, 어드민 페이지
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin page");
    }

    @GetMapping("/user") //유저 컨트롤러, 유저 페이지
    public ResponseEntity<String> user() {
        return ResponseEntity.ok("user page");
    }
}
