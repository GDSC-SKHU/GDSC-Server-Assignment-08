package com.example.jwt.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenDTO {
    private String grantType; //인증 받을 형식, Bearer 사용했음
    private String accessToken; //서버에서 사용자가 정상적으로 로그인을 마치면 사용자 인증 정보를 포함한 토큰
    private String refreshToken;// 억세스 만료될 때 재발급을 위한

}
