package com.gdsc.jwtexample.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Builder
@Data
public class TokenDTO {
    private String grantType; // 인증 인가 형식 (Bearer type)
    private String accessToken; // 접근
    private String refreshToken; //만료 시 재발급
}
