package gdsc.skhu.jwtskhu.jwt;

import gdsc.skhu.jwtskhu.domain.dto.TokenDTO;
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

import java.net.MalformedURLException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;
@Slf4j
@Component//컨테이너에 등록
public class TokenProvider {//토큰의 생성, 토큰의 유효성을 검사
    private final Key key;
    private final long validityTime;//유효 시간

    /**
     * Bean이 생성되고 의존성 주입을 받은 후에 secret 값을 Base64 Decode해서 key 변수에 할당
     * @param secretKey
     * @param validityTime
     */
    public TokenProvider(
           @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.token-validity-in-milliseconds}") long validityTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.validityTime = validityTime;
    }

    /**
     * Authentication 객체의 권한정보를 이용해서 토큰을 생성
     * @param authentication
     * @return
     */
    public TokenDTO createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()//authentication의 객체에서 인가정보를 가져와 stream으로 만든다.
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        long now = (new Date()).getTime();//현재 시간
        Date tokenExpiredTime = new Date(now + validityTime);//토큰 만료시간 = 현재 시간 + 정해준 만료 시간
        //AccessToken 생성한다.
        String accessToken = Jwts.builder().setSubject(authentication.getName()).claim("auth", authorities).setExpiration(tokenExpiredTime).signWith(key, SignatureAlgorithm.HS256).compact();
        //RefreshToken 생성
        String refreshToken = Jwts.builder().setExpiration(tokenExpiredTime).signWith(key, SignatureAlgorithm.HS256).compact();
        //TokenDTO로 반환
        return TokenDTO.builder().grantType("Bearer")//익명(Bearer)방식
                .accessToken(accessToken)
                .refreshToken(refreshToken).build();


    }

    public Authentication getAuthentication(String accessToken) {//Token에 담겨있는 정보를 이용하여 Authentication 객체 리턴
        Claims claims = parseClaims(accessToken);//Claims 객체 추출
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 담겨있지 않은 토큰입니다.");
        }
        //클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        // UserDetails 객체를 생성해서 UsernamePasswordAuthenticationToken 형태로 리턴 -> SecurityContext 사용을 위함
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();//토큰을 복호하여 Claims를 반환
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public boolean validateToken(String token) {//토큰 검증
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);//암호화된 서명을 검증한다.
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException exception) {//Invalid Token
            log.info("Invalid JWT Token", exception);
        } catch (ExpiredJwtException e) {//만료 토큰
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {//지원하지 않느 토큰
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {//빈 토큰
            log.info("JWT claims string is empty.",e);
        }
        return false;
    }
}
