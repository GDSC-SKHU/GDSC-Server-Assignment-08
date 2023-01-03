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

// @Bean을 사용해 수동으로 빈을 등록해줄 때에는 메소드 이름으로 빈 이름이 결정된다.
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                .httpBasic().disable()
                // csrf : 인터넷 사용자(희생자)가 자신의 의지와는 무관하게
                // 공격자가 의도한 행위(수정, 삭제, 등록 등)를 특정 웹사이트에 요청하게 만드는 공격
                // 왠만하면 끄지말자 대신 csrf 토큰이랑 같이 보내야함
                .csrf().disable()
                // .sessionManagement().sessionCreationPolicy( SessionCreationPolicy.정책상수)
                //sessionCreationPolicy : 스프링시큐리티 세션정책
                // SessionCreationPolicy.STATELESS : 스프링시큐리티가 생성하지도않고 기존것을 사용하지도 않음
                // ->JWT 같은토큰방식을 쓸때 사용하는 설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()// Request에 인증, 인가(권한 있냐?)를 부여하겠다.
                .antMatchers("/index", "/login").permitAll()  // /index /login 은 인가가 필요없다.
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")// /user  uri는 USER 롤 또는 ADMIN 롤이 있어야 접속가능
                .antMatchers("/admin").hasRole("ADMIN") // /admin uri는 ADMIN 롤이 있어야 접속가능.
                .anyRequest().authenticated() // 그 외에는 인증된 모든 사용자가 URL을 허용하도록 지정합니다.
                .and()
                // addFilterBefore : 지정된 필터 앞에 커스텀 필터를 추가 (UsernamePasswordAuthenticationFilter 보다 먼저 실행된다)
                // JwtFilter 를 등록한다.
                // SecurityContext를 사용하기 때문에 앞단의 필터에서 SecurityContext가 설정되고 난뒤 필터를 둔다.
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}