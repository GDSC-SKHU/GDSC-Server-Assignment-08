package com.gdsc.jwtexample.service;

import com.gdsc.jwtexample.domain.Member;
import com.gdsc.jwtexample.repository.MemberRepository;
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
    private final PasswordEncoder passwordEncoder; //SecurityConfig에서 설정해준 passwordEncoder bean 주입

    //username을 전달 받고 User 찾아서 UserDetails 객체로 리턴
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return memberRepository.findByMemberId(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException("해당 ID를 가진 유저를 찾을 수 없습니다.")); //없으면 출력
    }

    // 해당하는 User 의 데이터가 존재한다면 UserDetails 객체로 만들어서 리턴
    private UserDetails createUserDetails(Member member) {
        return User.builder()
                .username(member.getUsername()) //username 생성
                //DB에 저장하는 User 객체를 만들기 위한 User.build에서 해당 객체의 Password를 passwordEncoder.encode(password)를 통해 객체를 만들고, DB에 저장해줍니다.
                .password(passwordEncoder.encode(member.getPassword()))
                .roles(member.getRoles().toArray(new String[0]))
                .build();
    }
}
