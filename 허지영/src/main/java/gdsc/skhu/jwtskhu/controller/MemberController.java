package gdsc.skhu.jwtskhu.controller;

import gdsc.skhu.jwtskhu.domain.DTO.LoginDTO;
import gdsc.skhu.jwtskhu.domain.DTO.TokenDTO;
import gdsc.skhu.jwtskhu.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j // log4j와 같은 다양한 로깅 프레임 워크에 대한 추상화(인터페이스) 역할을 하는 라이브러리
@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/login") // 로그인 페이지
    public TokenDTO login(@RequestBody LoginDTO memberLoginRequestDTO){
        String memberID=memberLoginRequestDTO.getMemberId();
        String password = memberLoginRequestDTO.getPassword();
        TokenDTO tokenDTO = memberService.login(memberID, password);
        return tokenDTO;
    }

    @GetMapping("/index") // main 페이지
    public ResponseEntity<String> main() {
        return ResponseEntity.ok("main");
    }

    @GetMapping("/admin") // admin 페이지
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin");
    }

    @GetMapping("/user") // user 페이지
    public ResponseEntity<String> user() {
        return ResponseEntity.ok("user");
    }

}