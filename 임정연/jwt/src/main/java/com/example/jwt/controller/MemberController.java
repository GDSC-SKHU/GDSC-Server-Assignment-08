package com.example.jwt.controller;

import com.example.jwt.domain.DTO.LoginDTO;
import com.example.jwt.domain.DTO.TokenDTO;
import com.example.jwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j  //simple logging facade for JAVA, 추상 로깅 프레임워크, 단독 사용X
@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    //로그인
    @PostMapping("/login")
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

    //어드민 페이지
    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin");
    }

    //유저 페이지
    @GetMapping("/user")
    public ResponseEntity<String> user() {return ResponseEntity.ok("user");
    }
}
