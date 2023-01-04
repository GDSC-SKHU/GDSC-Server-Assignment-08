package gdsc.skhu.jwtskhu.jwt;

import gdsc.skhu.jwtskhu.domain.DTO.TokenDTO;
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
            @Value("${jwt.secret}") String secretKey, // secret키를 ${jwt.secret} 키에서 가져옴. application.yml(resources/application.yml)파일에 작성하면 해당 value를 가져 올 수 있음
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }

    public TokenDTO createToken(Authentication authentication){ // 토큰 생성
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")); // 권한

        long now = (new Date()).getTime(); // 현재 시간
        Date tokenExpiredTime = new Date(now + validityTime); // 토큰 만료시간

        String accessToken = Jwts.builder()
                .setSubject(authentication.getName()) // 유저 이름
                .claim("auth", authorities) // 권한 정보
                .setExpiration(tokenExpiredTime) // 토큰 만료 기간
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        String refreshToken = Jwts.builder() // refreshToken 생성해줌
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken) // accesssToken
                .refreshToken(refreshToken) // refreshToken
                .build();
    }

    // 토큰의 정보 가져옴
    public UsernamePasswordAuthenticationToken getAuthentication(String accessToken){
        Claims claims = parseClaims(accessToken); //accessToken -> claims 가져옴

        if(claims.get("auth") == null){ // 권한 정보가 없는 토큰
            throw new RuntimeException("권한 정보가 담겨있지 않은 토큰입니다");
        }

        // claims에서 권한 정보를 가져옴
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());


        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }


    // 토큰 정보 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        }
        // jwt 예외처리
        catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e); // 잘못된 토큰
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e); // 만료된 토큰
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e); // 지원되지 않는 토큰
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e); // 클레임 문자열이 비어있음
        }
        return false;
    }

    private Claims parseClaims(String accessToken) { // 복호화
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) { // 토큰 기한 만료
            return e.getClaims();
        }
    }

}
