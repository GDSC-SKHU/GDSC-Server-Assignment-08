package gdsc.skhu.jwt.service;


import gdsc.skhu.jwt.domain.Member;
import gdsc.skhu.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class JwtUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {//loadUserByUsername() 메소드를 오버라이드
        return memberRepository.findByMemberId(username)//MemberId로 username찾기
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException("해당하는 유저를 찾을 수 없습니다."));
                //만약 해당 username의 사용자 정보가 없다면 UsernameNotFoundException 예외를 던져준다.
    }

    // DB 에 User 값이 존재한다면 UserDetails 객체로 만들어서 리턴
    private UserDetails createUserDetails(Member member){
        return User.builder()
                .username(member.getUsername())
                .password(passwordEncoder.encode(member.getPassword()))
                .roles(member.getRoles().toArray(new String[0]))
                .build();
    }
}
/**
 * UserDetailsService 인터페이스를 구현한 클래스이다.
 * loadUserByUsername 메소드를 오버라이드 하는데 여기서 넘겨받은 UserDetails 와 Authentication 의 패스워드를 비교하고 검증하는 로직을 처리한다.
 * DB 에서 username 을 기반으로 값을 가져오기 때문에 아이디 존재 여부도 자동으로 검증 된다.
 */

