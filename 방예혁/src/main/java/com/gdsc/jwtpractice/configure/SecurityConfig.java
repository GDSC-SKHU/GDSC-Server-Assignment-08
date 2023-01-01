package com.gdsc.jwtpractice.configure;

import com.gdsc.jwtpractice.jwt.JwtFilter;
import com.gdsc.jwtpractice.jwt.TokenProvider;
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

@Configuration // @Bean으로 스프링 빈을 만들고 스프링 프로젝트가 시작될 때 Spring Security 설정 내용에 반영되도록 함
@EnableWebSecurity // Spring Security 활성화 (기본적인 Web 보안 활성화)
@RequiredArgsConstructor // final 또는 @NotNull이 붙은 필드들을 매개변수로 하는 생성자를 자동 생성해주는 lombok 어노테이션
public class SecurityConfig {

    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                 // rest api이므로 기본설정(비인증시 로그인폼 화면으로 리다이렉트) 사용 안함
                .httpBasic().disable()
                 // rest api에서는 csrf 공격으로부터 안전하고 매 요청마다 csrf 토큰을 받지 않아도 되기에 disable()
                .csrf().disable()
                 // ".STATELESS" 세션을 통한 인증 메커니즘을 사용하지 않겠다. (토큰 개념 사용하기 위함)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()

                 // 시큐리티 처리에 HttpServletRequest를 이용함
                .authorizeRequests()
                 // "/index", "/login"로 시작하는 uri 요청은 별도의 인증 절차 없이 허용
                .antMatchers("/index", "/login").permitAll()
                 // "/user"로 시작하는 uri 요청은 인증 완료 후 [USER, ADMIN] 이 중 하나 이상의 권한을 가진 사용자만 접근 허용
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
                 // "/admin" uri 요청은 인증 완료 후 [ADMIN] 권한을 가진 사용자만 접근 허용
                .antMatchers("/admin").hasRole("ADMIN")
                 // 이외에 모든 uri 요청은 인증을 완료해야 접근 허용
                .anyRequest().authenticated()

                .and()

                 // JwtFilter를 UsernamePasswordAuthenticationFilter 이전에 등록하는 설정
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // PasswordEncoder: Spring Security에서 제공하는 인터페이스, 구현체를 빈으로 등록해야 사용 가능
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}