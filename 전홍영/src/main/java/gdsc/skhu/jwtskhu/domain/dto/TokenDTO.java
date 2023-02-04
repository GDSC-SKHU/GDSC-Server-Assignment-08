package gdsc.skhu.jwtskhu.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenDTO {
    private String grantType;//인가, 인증 형식
    private String accessToken;
    private String refreshToken;//access 토큰 만료시 재발급을 위한 토큰(JWT 인증 방식은 제 3자에게 탈취당할 경우 보안이 취약하여 유효기간을 정해준다)
}
