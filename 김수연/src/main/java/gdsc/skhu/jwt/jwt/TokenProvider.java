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

/**
 * 토큰의 생성, 토큰의 유효성 검증등을 담당할 TokenProvider
 * TokenProvider: 유저 정보로 JWT 토큰을 만들거나 토큰을 바탕으로 유저 정보를 가져옴
 */

@Slf4j
@Component
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
    /*
		토큰 생성 메서드
   */
    public TokenDTO createToken(Authentication authentication) {
        // 권한들 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        long now = (new Date()).getTime();//yml에서 설정한 토큰 시간 설정
        // Access Token 생성
        java.util.Date tokenExpiredTime = new java.util.Date(now + validityTime);
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(tokenExpiredTime)// set Expire Time
                .signWith(key, SignatureAlgorithm.HS256)// 사용할 암호화 알고리즘과
                // signature 에 들어갈 secret값 세팅
                .compact();
        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(tokenExpiredTime)// set Expire Time
                .signWith(key, SignatureAlgorithm.HS256)// 사용할 암호화 알고리즘과
                // signature 에 들어갈 secret값 세팅
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

    }
    /*
	   Token에 담겨있는 정보를 이용해 Authentication 객체를 반환하는 메서드
	 */
    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 담겨있지 않은 토큰입니다.");

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
        /*
          토큰을 파싱하고 발생하는 예외를 처리, 문제가 있을 경우 false 반환
         */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
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
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }}

/**
 * JWT 토큰에 관련된 암호화, 복호화, 검증 로직은 다 이곳에서 이루어진다.
 *  생성자
 *  - application.yml 에 정의해놓은 jwt.secret 값을 가져와서
 *   JWT 를 만들 때 사용하는 암호화 키값을 생성한다.
 *

 /** generateTokenDto
 * 유저 정보를 넘겨받아서 Access Token 과 Refresh Token 을 생성한다
 * 넘겨받은 유저 정보의 authentication.getName() 메소드가 username 을 가져온다.
 * 여기서 username 으로 Member ID 를 저장했기 때문에 해당 값이 설정된다.
 * Access Token 에는 유저와 권한 정보를 담고 Refresh Token 에는 아무 정보도 담지 않는다.
 * /


 /*
 * getAuthentication
 * JWT 토큰을 복호화하여 토큰에 들어 있는 정보를 꺼낸다.
 * Access Token 에만 유저 정보를 담기 때문에 명시적으로 accessToken 을 파라미터로 받게한다.
 * Refresh Token 에는 아무런 정보 없이 만료일자만 담았다.
 * UserDetails 객체를 생생성해서 UsernamePasswordAuthenticationToken 형태로 리턴하는데 SecurityContext 를 사용하기 위한 절차이다.
 * parseClaims 메소드는 만료된 토큰이어도 정보를 꺼내기 위해서 따로 분리했다.
*/

/**
 * validateToken
 * 토큰 정보를 검증
 * Jwts 모듈이 알아서 Exception 을 던져준다.
 */