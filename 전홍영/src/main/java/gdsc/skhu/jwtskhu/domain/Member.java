package gdsc.skhu.jwtskhu.domain;

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
    /*
    * UserDetails는 인증된 핵심 사용자 정보(권한, 비밀번호, 사용자명, 각종 상태)를 제공하기 위한 interface이다.
    * 기존에 만들어진 시스템에 존재하는   Member 클래스가 UserDetails에 구현체가 된다.
    * 추가적으로 시스템에서 사용자 관리 시나리오에 따라 isAccountNonExpired, isAccountNonLocked, isCredentailsNonExpire, isEnabled 구현하면 된다.
    * */
    @Id
    @Column(updatable = false, unique = true, nullable = false)
    private String memberId;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)//값 타입 컬렉션을 매핑할 때 사용한다.
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {//계정이 갖고 있는 권한 목록을 리턴한다.
        return this.roles.stream()//roles를 List로 만들어 반환
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {//계정의 패스워드를 리턴한다.
        return password;
    }

    @Override
    public String getUsername() {//계정의 이름(ID)을 리턴한다.
        return memberId;
    }

    @Override
    public boolean isAccountNonExpired() {//계정이 만료되지 않았는지를 리턴한다(true를 리턴하면 만료되지 않음을 의미한다.)
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {//계정이 잠겨있지 않은지를 리턴한다.(true를 리턴하면 계정이 잠겨있지 않음을 의미한다.)
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {//계정의 패스워드가 만료되지 않았는지를 리턴한다.(true를 리턴하면 패스워드가 만료되지 않음을 의미한다.)
        return true;
    }

    @Override
    public boolean isEnabled() {//계정이 사용 가능한 계정인지를 리턴한다.(true를 리턴하면 사용가능한 계정임을 의미한다.)
        return true;
    }
}
