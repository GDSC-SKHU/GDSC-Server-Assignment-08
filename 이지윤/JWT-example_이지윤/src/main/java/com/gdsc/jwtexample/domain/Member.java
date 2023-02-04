package com.gdsc.jwtexample.domain;

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
    //id
    @Id
    @Column(updatable = false, unique = true, nullable = false)
    private String memberId;

    //password
    @Column(nullable = false)
    private String password;

    //권한 목록
    @ElementCollection(fetch = FetchType.EAGER) //필드가 컬렉션 객체임을 알려줌.
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    //계정 권한 목록 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    // 계정 고유 값 리턴
    @Override
    public String getUsername() {
        return memberId;
    }

    //계정 password 리턴
    @Override
    public String getPassword() {
        return password;
    }

    //계정 만료 여부 (true = 만료 x)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    //계정 잠김 여부 (true = 잠김 x)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    //password 만료 여부 (true = 만료 x)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    //계정 활성화 여부 (true = 활성화)
    @Override
    public boolean isEnabled() {
        return true;
    }
}