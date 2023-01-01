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
public class TokenProvider {
    private final Key key;
    private final long validityTime;

    /*
       초기화
       key: application.yml에 작성한 (jwt: secret) 값을 가져와서 JWT 만들 때 사용하는 암호화 키 값을 생성
       validityTime: application.yml에 작성한 (jwt: token-validity-in-milliseconds) 값을 가져와서 만료 일자 지정
    */
    public TokenProvider(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }

    // 토큰 생성
    public TokenDTO createToken(Authentication authentication) {
        // 권한 정보
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // 현재 시간
        long now = (new Date()).getTime();

        // 토큰 만료 시간
        Date tokenExpiredTime = new Date(now + validityTime);

        /*
           AccessToken 생성
           payload "sub": 유저 이름
           payload "auth": 권한 정보
           payload "exp": 만료 기간
           header "alg": "HS256"
        */
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // RefreshToken 생성
        String refreshToken = Jwts.builder()
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // TokenDTO로 리턴
        return TokenDTO.builder()
                .grantType("Bearer") // Bearer 방식
                .accessToken(accessToken) // AccessToken
                .refreshToken(refreshToken) // RefreshToken
                .build();
    }

    // 토큰에 담겨있는 정보를 가져오는 메소드
    public Authentication getAuthentication(String accessToken) {
        // 받아온 AccessToken에서 Claims 추출
        Claims claims = parseClaims(accessToken);

        // 권한 정보가 담겨있지 않은 토큰을 받았을 때
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 위 과정을 무사히 통과하면 권한 정보가 있는 토큰임

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 생성해서 UsernamePasswordAuthenticationToken 형태로 리턴 -> SecurityContext 사용을 위함
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    // 넘어온 토큰이 유효한 토큰인지 판별하는 메소드, JWT가 알아서 Exception 던져줌
    public boolean validateToken(String token) {
        // 매개변수로 받아온 토큰이 유효하면 true 반환
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        }
        // 토큰이 유효하지 않으면 false 반환
        // MalformedJwtException: JWT가 올바르게 구성되지 않았을 때
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
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) { // 기한 만료된 토큰
            return e.getClaims();
        }
    }
}