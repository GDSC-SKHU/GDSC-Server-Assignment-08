package gdsc.skhu.jwt.jwt;

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
public class JwtFilter extends GenericFilterBean {
    private final TokenProvider tokenProvider;

    // Custom Filter
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = resolveToken((HttpServletRequest) request);  // 헤더에서 JWT를 받아옴
        // 토큰이 비어있지 않고, 토큰이 검증되었을 경우 유저 정보를 받아옴
        if(StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
            Authentication authentication = tokenProvider.getAuthentication(token);
            // 받아온 authentication 객체를 SecurityContextHolder에 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");        // HttpRequest에서 jwt를 헤더에 담아보낸 걸 가져옴
        // 토큰이 비어있지 않고, Bearer로 시작될 경우
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);        // "Bearer " 문자열빼고 jwt 내용이 시작되는 부분부터 가져옴.
        }
        return null;
    }
}
