package com.example.jwt.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Member implements UserDetails {
    // 아이디
    @Id
    @Column(updatable = false, unique = true, nullable = false)
    private String memberId;

    // 비밀번호
    @Column(nullable = false)
    private String password;

    // 즉시 로딩으로 관리
    @ElementCollection(fetch = FetchType.EAGER)

    // 우리가 만든 role을 불러옴 -> 여기선 어드민, 유저 이런거 받아옴
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    // 해당 사용자 계정의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    // 계정 이름 리턴
    @Override
    public String getUsername() {
        return memberId;
    }

    // 계정 비밀번호 리턴
    @Override
    public String getPassword() {
        return password;
    }

    // 계정이 만료되지 않았는지 리턴
    // true : 만료되지 않음
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겨있지 않은지 리턴
    // true : 잠겨있지 않음
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀번호가 만료되지 않았는지 리턴
    // true : 만료되지 않음
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 사용 가능한 계정인지 리턴
    // true : 사용가능한 계정
    @Override
    public boolean isEnabled() {
        return true;
    }
}