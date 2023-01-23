package gdsc.skhu.jwt.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenDTO {
    private String grantType;       // 토큰 인증 타입, JWT는 bearer 사용

    // 클라이언트가 갖고 있는 유저의 정보가 담긴 토큰, 이 정보를 활용해 서버는 응답을 진행 (접근)
    private String accessToken;

    // 짧은 수명을 가지는 Access Token에게 새로운 토큰을 발급해주기 위한 토큰, DB에 유저 정보와 같이 기록 (재발급)
    private String refreshToken;
}
