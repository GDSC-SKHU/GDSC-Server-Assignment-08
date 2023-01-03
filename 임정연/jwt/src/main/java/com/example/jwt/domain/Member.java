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
public class Member implements UserDetails { //userdetail란 Spring Security에서 사용자의 정보를 담는 인터페이스이다.
    // Spring Security에서 사용자의 정보를 불러오기 위해서 구현해야 하는 인터페이스
    @Id
    @Column(updatable = false, unique = true, nullable = false)
    private String memberId;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    @Override //해당 User의 권한을 리턴하는 곳
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream() //.stream() 개체 컬렉션을 처리함
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getUsername() {
        return memberId;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override //만료여부, true : 만료안됨
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override //계정 잠김 여부, true : 잠기지 않음
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override //비번 만료 여부, true: 만료 안됨
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override //사용자 활성화 여부, true : 활성화
    public boolean isEnabled() {
        return true;
    }
}