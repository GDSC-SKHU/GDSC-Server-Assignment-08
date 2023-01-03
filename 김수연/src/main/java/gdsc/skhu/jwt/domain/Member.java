package gdsc.skhu.jwt.domain;


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

    @Id
    @Column(updatable = false, unique = true, nullable = false)
    private String memberId;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Builder.Default
    private List<String> roles = new ArrayList<>();


    // 사용자의 권한을 콜렉션 형태로 반환
    // 단, 클래스 자료형은 GrantedAuthority를 구현해야함
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()//내가 가지고 있는 롤을 스트림하겠다.
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
        /*
        getAuthorities()
        이 메소드는 사용자의 권한을 콜렉션 형태로 반환해야하고,
        콜렉션의 자료형은 무조건적으로 GrantedAuthority를 구현해야한다.
         */
    @Override
    public String getUsername() {
        return memberId;
    }

    @Override
    public String getPassword() {
        return password;
    }
    //계정 만료 여부 반환 (true = 만료되지 않음을 의미)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    //계정 잠금 여부 반환 (true = 잠금되지 않음을 의미)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    //패스워드 만료 여부 반환 (true = 만료되지 않음을 의미)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    //계정 사용 가능 여부 반환 (true = 사용 가능을 의미)
    @Override
    public boolean isEnabled() {
        return true;
    }
}
