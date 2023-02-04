package com.example.jwt.configure;

import com.example.jwt.jwt.JwtFilter;
import com.example.jwt.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
@EnableWebSecurity 어노테이션을 달면 SpringSecurityFilterChain이 자동으로 포함됩니다.
 */
@Configuration
@EnableWebSecurity //스프링시큐리티 사용을 위한 어노테이션 선언해줌
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider; //토큰을 부여해 줌
/*
Security의 가장 핵심적인 클래스로 springSecurityFilterChain이라는 네임벨류 Bean이다
역할은 FilterChainProxy를 만들어 DelegatingFilterProxy의 실제 처리를 담당한다, 반환값이 있고 빈으로 등록
컴포넌트 기반의 보안 설정이 가능해진다

HttpSecurityConfiguration은 HttpSecurity Bean을 주입해주는 Class

 */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .httpBasic().disable()//Http basic Auth 기반으로 로그인 인증창이 뜸, disable 시에 증창 뜨지 않음
                .csrf().disable()//rest api이므로 crsf보안이 필요 없기 때문에 disable
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//jwt token으로 인증하므로 stateless하도록 처리
                .and()
                .authorizeRequests() //특정 리소스의 접근 허용 또는 특정 권한을 가진 사용자만 접근 가능하게 할 수 있음
                //antMatchers는 특정 리소스에 대해서 권한을 설정
                .antMatchers("/index", "/login").permitAll() //유저든 어드민이든 누구에게나 허용됨, 인증절차 없음
                .antMatchers("/user").hasAnyRole("USER", "ADMIN") //유저 페이지는 유저랑 어드민 둘 다 허용됨
                .antMatchers("/admin").hasRole("ADMIN") //어드민 페이지는 admin 레벨의 권한을 가진 사용자만 허용됨
                .anyRequest().authenticated() //모든 리소스를 의미, 접근 가능한 리소스를 설정하고 그외 나머지 리소스들은 무조건 인증을 완료해야 접근가능
                .and()
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class); //지정된 필터 앞에 커스텀 필터를 추가
        return http.build();
    }

    @Bean //빈을 하는 이유는 아이디/암호를 입력해서 로그인 처리를 하려면 반드시 암호가 인코딩되어 있어야 하기 떄문
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); //이걸 활용하면, PasswordEncoder를 반환받을 수 있음
    }
}
