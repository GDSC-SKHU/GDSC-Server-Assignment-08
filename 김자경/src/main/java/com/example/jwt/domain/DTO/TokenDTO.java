package com.example.jwt.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenDTO {
    private String grantType; // 허가 받는 방식 -> 여기선 Bearer 방식 사용
    private String accessToken; // 요청에 대한 다양한 정보를 담음 + 실질적 인증
    private String refreshToken;// Access Token의 만료 기간 조정
}