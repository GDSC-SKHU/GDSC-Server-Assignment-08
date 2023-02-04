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
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
//토큰 제공자
public class TokenProvider {
    private final Key key;
    private final long validityTime;

    public TokenProvider(
            //환경변수 설정한 거 불러오기
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }
    //스프링시큐리티를 관리하는 인증 정보로 가지고 오는 것
    public TokenDTO createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();

        Date tokenExpiredTime = new Date(now + validityTime); //토큰 만료시간 지정

        //토큰 만들기
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        //만료시 새로 지급 되는 토큰 만들기
        String refreshToken = Jwts.builder()
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        //여기까지 토큰 만드는 매소드
        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
    //스프링시큐리티
    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        //예외 설정)권한 정보가 담겨있지 않은 토큰 걸러내기
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 담겨있지지 않은 토큰입니다.");
        }

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        //여기까지 인증 정보를 가져오는 매소드
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    //유효한 토큰 인지를 확인 하는 매소드
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;  //앞에 예외가 발생안한다면 이것은 유효한 토큰이다
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e); //만료된 토큰이 넘어올 경우
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e); //변조된 혹은 형식에 맞지 않은 토큰이 넘어올 경우
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e); //페이로드에 담겨오는 정보(는 무슨 정보더라)는 변경이 가능하다
        }
        return false; //앞에 지정된 토큰이 넘어오면 그것은 유효하지 않음
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims(); //만료된 토큰이 넘어올 경우 새 토큰을 발행해 주어야함
        }
    }
}
