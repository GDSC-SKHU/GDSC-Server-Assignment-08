package com.gdsc.jwtpractice.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

// DTO(Data Transfer Object): 데이터의 전송을 담당하는 객체
@Builder
@Data
@AllArgsConstructor
public class TokenDTO {
    private String grantType; // 인증, 인가 형식
    private String accessToken; // 요청에 대한 다양한 정보를 담고 실질적 인증 토큰
    private String refreshToken; // Access Token의 만료 시 재발급할 수 있는 토큰
}