package com.example.jwt.jwt;

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
//jwt 토큰이 넘어올 때 필터링 해준다
public class JwtFilter extends GenericFilterBean {

    private final TokenProvider tokenProvider;
//모든 토큰은 스트링 형태이다
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = resolveToken((HttpServletRequest) request);
        if(StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
            Authentication authentication = tokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }  //유효한 올바른 토큰임을 인지 하고 권한?인증정보?를 넘겨줌
        chain.doFilter(request, response); //필터링을 하라
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        //Bearer타입의 인증 방식을 사용하겠다 (토큰 입력 방식 : Bearer [토큰입력])
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null; //if문을 끝마치지 않고 중간에 끝나면 스프링시큐리티는 아무것도 반환하지 않는다
    }
}
