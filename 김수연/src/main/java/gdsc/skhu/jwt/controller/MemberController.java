package gdsc.skhu.jwt.controller;


import gdsc.skhu.jwt.domain.DTO.LoginDTO;
import gdsc.skhu.jwt.domain.DTO.TokenDTO;
import gdsc.skhu.jwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAnyRole;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    //로그인
    @PostMapping("/login")
    public TokenDTO login(@RequestBody LoginDTO memberLoginRequestDTO){
        String memberID=memberLoginRequestDTO.getMemberId();
        String password = memberLoginRequestDTO.getPassword();
        TokenDTO tokenDTO = memberService.login(memberID, password);
        return tokenDTO;
    }
    //admin페이지
    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin");
    }
    //user페이지
   @GetMapping("/user")
   public ResponseEntity<String> user() {
        return ResponseEntity.ok("user");    }
}

