package gdsc.skhu.jwtskhu.configure;

import gdsc.skhu.jwtskhu.jwt.JwtFilter;
import gdsc.skhu.jwtskhu.jwt.TokenProvider;
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

@Configuration // Bean 등록 어노테이션
@EnableWebSecurity // pringSecurityFilterChain 자동으로 포함
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()// Http basic Auth  기반으로 로그인 인증창이 뜸.  disable 시에 인증창 뜨지 않음.
                .csrf().disable() // rest api이므로 csrf 보안이 필요없으므로 disable처리.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // jwt token으로 인증하므로 stateless 하도록 처리.
                .and()
                .authorizeRequests()
                // index와 login으로 시작하는 요청은 인증하지 않아도 허용
                .antMatchers("/index", "/login").permitAll()
                // user로 시작하는 요청은 USER, ADMIN 중 권한을 가진 사용자만 접근 허용
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
                // admin으로 시작하는 요청은 ADMIN 권한을 가진 사용자만 접근 허용
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated() // 인증권한이 필요한 페이지.
                .and()
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class); // UsernamePasswordAuthenticationFilter 이전에 등록
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() { // 비밀번호 암호화

        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
