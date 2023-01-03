package gdsc.skhu.jwt.domain.DTO;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenDTO {
    private String grantType; //grantType은 JWT 대한 인증 타입, 여기서는 Bearer를 사용
    private String accessToken;//서버 측에서는 사용자가 정상적으로 로그인을 마치면 사용자 인증 정보를 포함하는 Access Token
    private String refreshToken;//이를(accessToken) 재발급할 수 있는 Refresh Token 을 생성

}
