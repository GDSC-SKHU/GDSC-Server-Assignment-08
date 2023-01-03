package gdsc.skhu.jwt.service;


import gdsc.skhu.jwt.domain.DTO.TokenDTO;
import gdsc.skhu.jwt.jwt.TokenProvider;
import gdsc.skhu.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @Transactional
    public TokenDTO login(String memberId, String password){
        // 1. Login ID/PW 를 기반으로 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);

        // 2. 실제로 검증 (사용자 비밀번호 체크) 이 이루어지는 부분
        //authenticate 메서드가 실행이 될 때 JwtUserDetailsService 에서 만들었던
        //loadUserByUsername 메서드가 실행됨
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenDTO tokenDTO = tokenProvider.createToken(authentication);

        // 4. 토큰 발급
        return tokenDTO;
    }

}
