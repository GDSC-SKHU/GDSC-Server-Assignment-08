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
@EnableWebSecurity //@EnableWebSecurity : 기본적인 Web 보안을 활성화
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()//httpBasic 방식 대신 Jwt를 사용하기 때문에 disable로 설정
                // token을 사용하는 방식이기 때문에 csrf를 disable한다.
                .csrf().disable()//API를 작성하는데 프런트가 정해져있지 않기 때문에 csrf설정은 우선 꺼놓는다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//Jwt를 사용하기 때문에 session을 stateless로 설정한다.
                // stateless로 설정 시 Spring Security는 세션을 사용하지 않는다.
                .and()
                .authorizeRequests()//HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정한다.
                .antMatchers("/index", "/login").permitAll()//antMatchers 설정한 리소스의 접근을 인증절차 없이 허용한다.
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")//hasAnyRole(String...): 사용자가 주어진 어떤권한이라도 있으면 허용한다.
                .antMatchers("/admin").hasRole("ADMIN")//hasRole(String): 사용자가 주어진 역할이 있다면 접근을 허용한다.
                .anyRequest().authenticated()//모든 리소스를 의미하며 접근허용 리소스 및 인증후 특정 레벨의 권한을 가진 사용자만 접근가능한 리소스를 설정하고
                // 그외 나머지 리소스들은 무조건 인증을 완료해야 접근이 가능하게 한다.
                .and()
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    //비밀번호 암호화에 사용되는 PasswordEncoder
    // Spring Security에서 제공하는 PasswordEncoder는 인터페이스이기 때문에
    // 구현체를 빈으로 등록해야 사용 가능
    @Bean
    public PasswordEncoder passwordEncoder() {

        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}