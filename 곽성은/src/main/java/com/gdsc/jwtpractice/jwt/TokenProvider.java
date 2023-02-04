package com.gdsc.jwtpractice.jwt;

import com.gdsc.jwtpractice.domain.DTO.TokenDTO;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
// 토큰의 생성, 토큰의 유효성 검증 클래스
public class TokenProvider {
    private final Key key;
    private final long validityTime;


    public TokenProvider(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }

    // 토큰 생성
    public TokenDTO createToken(Authentication authentication) {
        // 권한 가져옴
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // 현재 시간
        long now = (new Date()).getTime();

        // 토큰 만료 시간 저장
        Date tokenExpiredTime = new Date(now + validityTime);

        // AccessToken 생성
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256) // 암호화 알고리즘, secret 값 설정
                .compact();

        // RefreshToken 생성
        String refreshToken = Jwts.builder()
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // TokenDTO로 리턴
        return TokenDTO.builder()
                .grantType("Bearer") // Bearer 방식
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // 토큰에 담겨있는 정보를 가져오는 메소드
    public Authentication getAuthentication(String accessToken) {
        // Claims 객체 추출
        Claims claims = parseClaims(accessToken);

        // 권한 정보가 담겨있지 않은 토큰을 받았을 때(null)
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 생성해서 UsernamePasswordAuthenticationToken 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    // 넘어온 토큰이 유효한 토큰인지 판별, 예외 처리하는 메소드
    public boolean validateToken(String token) {
        // 매개변수로 받아온 토큰이 유효하면
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        }
        // 토큰이 유효하지 않으면, JWT가 올바르게 구성되지 않은 경우
        catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }

    // 토큰을 복호화해서 정보 리턴
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody(); // 복호화
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}