package com.gdsc.jwtexample.configure;

import com.gdsc.jwtexample.jwt.JwtFilter;
import com.gdsc.jwtexample.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration //설정 파일을 만들기 위한 어노테이션 or Bean을 등록하기 위한 어노테이션임.
@EnableWebSecurity //스프링 AutoConfiguration이며 우리가 쉽게 MVC Security세팅을 할 수 있게 도와줌.
@RequiredArgsConstructor //final이 붙거나 @NotNull 이 붙은 필드의 생성자를 자동 생성해주는 lombok annotation
public class SecurityConfig {

    private final TokenProvider tokenProvider;

    //@EnableWebSecurity 내에 import 되어있는 HttpSecurityConfiguration는 HttpSecurity Bean을 주입해주는 Class.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()// Http basic Auth  기반으로 로그인 인증창이 뜸. disable 시에 인증창 뜨지 않음.
                .csrf().disable()// api서버 이므로 csrf 보안이 필요없으므로 disable처리.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //STATELESS 는 인증 정보를 서버에 담아 두지 않는다. jwt token으로 인증하므로 stateless 하도록 처리.
                .and()
                .authorizeRequests() //각 경로 path 별 권한 처리
                .antMatchers("/index", "/login").permitAll() //인증 절차 없어도 접근 허용
                .antMatchers("/user").hasAnyRole("USER", "ADMIN") //user는 USER,ADMIN 접근 허용
                .antMatchers("/admin").hasRole("ADMIN") //admin페이지는 role이 ADMIN인 경우에만 접근 허용
                .anyRequest().authenticated() //그외 나머지 리소스들은 무조건 인증을 완료해야 접근이 가능
                .and()
                //인증 처리하는 UsernamePasswordAuthenticationFilter 외의 tokenProvider라는 커스텀 필터를 추가함. 후자의 필터보다 먼저 실행됨.
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    //passwordEncoderfactories에서의 create~~를 사용하여 비밀번호 암호화
    //db에서 조회 요청 시 bcrypt로 인코딩 된 결괏값을 확인할 수 있음.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}