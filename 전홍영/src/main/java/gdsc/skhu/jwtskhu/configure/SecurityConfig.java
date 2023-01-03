package gdsc.skhu.jwtskhu.configure;

import antlr.Token;
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

@Configuration
@EnableWebSecurity//기본적인 Web 보안을 활성화 해주는 annotation
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http//HttpSecurity는 Spring Security 각종 설정을 담당한다.
                .httpBasic().disable()//http basic Auth 기반으로 로그인 인증창이 뜬다. disable() 시에는 뜨지 않는다.
                .csrf().disable()//rest api이므로 csrf 보안이 필요없으므로 disable 처리
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//jwt token으로 인증하므로 stateless 하도록 처리
                .and()
                .authorizeRequests()
                .antMatchers("/index", "/login").permitAll()//"/index", "/login"은 허용
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")//"/user"는 USER, ADMIN 권한이 있어야 접근 가능
                .antMatchers("/admin").hasRole("ADMIN")//"/admin"은 ADMIN 권한 필요
                .anyRequest().authenticated()//모든 리소스를 의미하며 접근허용 리소스 및 인증후 특정 레벨의 권한을 가진 사용자만 접근가능한 리소스를 설정하고 그외 나머지 리소스들은 무조건 인증을 완료해야 접근이 가능하다는 의미입니다.
                .and()
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);//지정된 필터 앞에 커스텀 필터를 추가(UserPasswordAuthenticationFilter 보다 new JwtFilter(TokenProvider)가 먼저 실행된다.)
        return http.build();
    }

    @Bean//password 인코더 빈 등록
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
