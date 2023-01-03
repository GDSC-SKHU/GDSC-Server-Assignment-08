package com.gdsc.jwtexample.jwt;

import com.gdsc.jwtexample.domain.DTO.TokenDTO;
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


//토큰 생성, 토큰의 유효성 검증을 위한 클래스
@Slf4j
@Component
public class TokenProvider {
    private final Key key;
    private final long validityTime;

    public TokenProvider(
            @Value("${jwt.secret}") String secretKey, //암호화 key값 생성
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) { //만료일자 지정
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }

    //토큰 생성 메서드
    public TokenDTO createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime(); //지금 시간
        Date tokenExpiredTime = new Date(now + validityTime); //만료 시간
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        //refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer") //Bearer type 사용
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    //Token에 담겨있는 정보를 이용해 Authentication 객체를 반환하는 메서드
    public Authentication getAuthentication(String accessToken) {
        //토큰 복호화
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        //클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    //토큰 검증, 토큰을 파싱하고 발생하는 예외를 처리, 문제가 있을 경우 false 반환
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e); //잘못된 JWT 서명
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e); //만료된 JWT 토큰
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e); //지원되지 않는 JWT token
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e); //JWT토큰이 잘못됨.
        }
        return false;
    }

    //토큰 복호화해서 정보 리턴
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
