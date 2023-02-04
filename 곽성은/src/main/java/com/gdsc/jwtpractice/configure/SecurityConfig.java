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

@Configuration
@EnableWebSecurity // 기본적인 Web 보안 활성화
@RequiredArgsConstructor // final 또는 @NotNull이 붙은 필드들을 매개변수로 하는 생성자를 자동 생성
public class SecurityConfig {

    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // http basic Auth 기반으로 로그인 인증창이 뜸, rest api 사용하므로 disable
                .httpBasic().disable()
                // rest api 사용 시에는 disable
                .csrf().disable()
                 // jwt token 으로 인증하므로 stateless(세션 사용하지않음) 하도록 처리
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()

                 // 시큐리티 처리에 HttpServletRequest를 이용함, path 별 권한 처리
                .authorizeRequests()
                 // 인증 절차 없이 허용
                .antMatchers("/index", "/login").permitAll()
                 // USER, ADMIN 중 하나 이상의 권한을 가진 user 만 접근 허용
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
                 // ADMIN 권한을 가진 user 만 접근 허용
                .antMatchers("/admin").hasRole("ADMIN")
                 // 이외에 모든 uri 요청은 무조건 인증을 완료해야 접근 허용
                .anyRequest().authenticated()

                .and()

                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // 비밀번호 암호화, 구현체를 빈으로 등록해야 사용 가능
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}