package gdsc.skhu.jwt.jwt;

import gdsc.skhu.jwt.domain.DTO.TokenDTO;
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

    public TokenProvider(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);    // BASE64로 디코딩
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }


    public TokenDTO createToken(Authentication authentication) {        // 토큰 생성
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date tokenExpiredTime = new Date(now + validityTime);       // 토큰만료일자
        String accessToken = Jwts.builder()                         // accessToken 생성
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        String refreshToken = Jwts.builder()                        // refreshToken 생성
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // 토큰 2개를 DTO 객체로 묶어서 보냄
        return TokenDTO.builder()
                .grantType("Bearer")        // 인증타입
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(String accessToken) {   // Token에 담겨있는 정보를 이용해 Authentication 객체를 반환
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) {       // 인증정보가 비어있을 경우 예외 발생
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 인증정보를 문자열로 변환해서 SimpleGrantedAuthority 객체들의 배열로 만듬
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public boolean validateToken(String token) {    // 토큰 유효성 검사
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {   
            log.info("Invalid JWT Token", e);   // 유효하지 않는 토큰
        } catch (ExpiredJwtException e) {       // 만료된 토큰
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {   // 변조되거나 형식이 일치하지 않는 토큰
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {  // claim이 비어있음
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }

    private Claims parseClaims(String accessToken) {    // token body 만들기
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key).build()
                    .parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {   // 만료된 토큰일 경우 재발급이 필요하기 때문에 받아옴.
            return e.getClaims();
        }
    }
}
