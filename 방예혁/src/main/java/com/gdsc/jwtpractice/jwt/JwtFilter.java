package com.gdsc.jwtpractice.jwt;

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

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // resolveToken()를 이용해서 토큰을 받아옴
        String token = resolveToken((HttpServletRequest) request);

        // 토큰이 비어있지 않으면서 유효한 경우
        if(StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
            // 조건에 만족하면 토큰으로부터 유저 정보를 Authentication 객체에 저장
            Authentication authentication = tokenProvider.getAuthentication(token);
            
            // SecurityContext에 Authentication 객체를 저장 (인증 정보(authentication)를 Spring Security에게 넘김)
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }

    //  Request Header에서 토큰 값을 가져오는 메소드, "Authorization": "토큰 값"
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        // 가져온 값이 비어있지 않으면서 "Bearer "로 시작한다면
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            // "Bearer ~값~" 형식인데, "~값~"만 가져와서 반환
            return bearerToken.substring(7);
        }
        // 아니면 null 리턴
        return null;
    }
}