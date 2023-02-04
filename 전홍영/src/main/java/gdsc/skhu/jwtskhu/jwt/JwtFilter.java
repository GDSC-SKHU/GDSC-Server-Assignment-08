package gdsc.skhu.jwtskhu.jwt;

import io.jsonwebtoken.lang.Strings;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {//JWT 토큰을 파싱하거나 내려주어 헤더에 저장하는 JwtFilter
    private final TokenProvider tokenProvider;
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = resolveToken((HttpServletRequest) request);//헤더에서  토큰을 가져온다.
        if (Strings.hasText(token) && tokenProvider.validateToken(token)) {//토큰이 null이 아니고 tokenProvider에서 트큰을 검증해서 true가 반환되면
            Authentication authentication = tokenProvider.getAuthentication(token);//토큰에서 권한 객체를 추출
            SecurityContextHolder.getContext().setAuthentication(authentication);//SecurityContext에 authentication을 담는다.
        }
        chain.doFilter(request, response);//response를 이용해 응답의 필터링 작업
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");//request 헤더의 Authorization 값이 bearerToken에 저장
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {//bearerToken이 Bearer로 시작하고 null이 아니면
            return bearerToken.substring(7);//index 5부터 다음 글자를 반환
        }
        return null;
    }
}
