package gdsc.skhu.jwt.configure;


import gdsc.skhu.jwt.jwt.JwtFilter;
import gdsc.skhu.jwt.jwt.TokenProvider;
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
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {    // 필터링
        http
                .httpBasic().disable()      // JWT를 사용할 것이므로 기본 설정 사용X
                .csrf().disable()           // csrf 보안 사용X
                // // jwt token을 사용할 것이므로 세션 생성X
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()      // SecurityConfigurer를 사용한 후 SecurityBuilder를 반환
                // 다음 request들에 대한 사용 권한 지정
                .authorizeRequests()
                .antMatchers("/index", "/login").permitAll()        // /index와 /login은 누구나 접근 가능
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")   // /user는 'USER'와 'ADMIN' 권한을 가진 유저만 접근 가능
                .antMatchers("/admin").hasRole("ADMIN")             // /admin는 'ADMIN' 권한을 가진 유저만 접근 가능
                .anyRequest().authenticated()       // .anyRequest() 위에 설정을 제외한 요청은 모두 .authenticated() 인증이 필요한 요청으로 설정
                .and()
                // jwt token 필터를 id/password 인증 필터 전에 넣는다.
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // 비밀번호 암호화
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}