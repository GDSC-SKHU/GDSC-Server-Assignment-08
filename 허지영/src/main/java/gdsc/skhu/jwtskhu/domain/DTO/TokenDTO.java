package gdsc.skhu.jwtskhu.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenDTO {
    private String grantType; // 인증받고 형식 정해줌
    private String accessToken; // 접근할 때 사용
    private String refreshToken; // accesstoken이 만료될 때
}
