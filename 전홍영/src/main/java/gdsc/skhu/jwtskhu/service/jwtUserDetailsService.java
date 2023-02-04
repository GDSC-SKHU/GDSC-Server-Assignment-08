package gdsc.skhu.jwtskhu.service;


import gdsc.skhu.jwtskhu.domain.Member;
import gdsc.skhu.jwtskhu.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class jwtUserDetailsService implements UserDetailsService {
    /**
     * UserDetailsService는 Spring Security에서 유저의 정보를 가져오는 인터페이스이다.
     * Spring Security에서 유저의 정보를 불어오기 위해서 구현해야하는 인터페이스이다.
     */
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override//유저 정보를 불러와서 UserDetails로 리턴
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return memberRepository.findByMemberId(username)//ID로 Member를 찾는다.
                .map(this::createUserDetails)//UserDetails 객체를 생성
                .orElseThrow(() -> new UsernameNotFoundException("해당하는 유저를 찾을 수 없습니다."));
    }

    // 해당하는 User 의 데이터가 존재한다면 UserDetails 객체로 만들어서 리턴
    private UserDetails createUserDetails(Member member) {
        return User.builder()
                .username(member.getUsername())
                .password(passwordEncoder.encode(member.getPassword()))//멤버의 암호를 복호화하여 build
                .roles(member.getRoles().toArray(new String[0]))
                .build();
    }
}