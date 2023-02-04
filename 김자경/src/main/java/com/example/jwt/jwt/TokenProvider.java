package com.example.jwt.jwt;

import com.example.jwt.domain.DTO.TokenDTO;
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
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
// jwt 패키지를 생성 후 토큰의 생성, 토큰의 유효성 검증등을 담당
public class TokenProvider {
    private final Key key;
    private final long validityTime;

    public TokenProvider(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) {

        // 주입된 secretKey 값을 Base 64 Decode해서 key 변수에 할당
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }

    // JWT 생성
    // 사용자 정보를 가지고 AccessToken, RefreshToken을 생성하는 메서드
    public TokenDTO createToken(Authentication authentication) {

        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date tokenExpiredTime = new Date(now + validityTime); // 토큰 만료 기간

        // Access Token 생성
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // JWT로 인증 정보 조회
    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 메서드
    public Authentication getAuthentication(String accessToken) {

        // JWT에서 claims 추출 -> 토큰 복호화
        Claims claims = parseClaims(accessToken);

        // 권한 정보가 없음
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    // JWT의 유효성 및 만료일자 확인
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e); // 잘못된 JWT 서명입니다
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e); // 만료된 JWT 토큰입니다
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e); // 지원되지 않는 JWT 토큰입니다
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e); // JWT 토큰이 잘못되었습니다
        }
        return false;
    }

    // JWT 토큰 복호화해서 가져오기
    // parseClaims() : 만료된 토큰이어도 refresh token을 검증 후 재발급할 수 있도록 claims를 반환해 줌
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}