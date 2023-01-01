package com.gdsc.jwtpractice.domain;

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

// 사용자의 정보를 불러오기 위해서 UserDetails 인터페이스를 구현
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Member implements UserDetails {

    // 아이디 (Primary Key)
    @Id
    @Column(updatable = false, unique = true, nullable = false)
    private String memberId;

    // 비밀번호
    @Column(nullable = false)
    private String password;

    // 권한 목록, @ElementCollection: 해당 필드가 컬렉션 객체임을 JPA에게 알려줌
    @ElementCollection(fetch = FetchType.EAGER) // 연관된 엔티티 즉시 로딩
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    // 계정의 권한 목록을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    // 계정의 고유한 값을 리턴
    @Override
    public String getUsername() {
        return memberId;
    }

    // 계정의 비밀번호를 리턴
    @Override
    public String getPassword() {
        return password;
    }

    // 계정의 만료 여부 리턴, true: 만료되지 않음
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정의 잠김 여부 리턴, true: 잠기지 않음
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀번호 만료 여부 리턴, true: 만료되지 않음
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정의 활성화 여부 리턴, true: 활성화
    @Override
    public boolean isEnabled() {
        return true;
    }
}