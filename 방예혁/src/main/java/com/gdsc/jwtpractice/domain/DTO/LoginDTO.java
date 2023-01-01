package com.gdsc.jwtpractice.domain.DTO;

import lombok.Data;

// DTO(Data Transfer Object): 데이터의 전송을 담당하는 객체
@Data
public class LoginDTO {
    private String memberId;
    private String password;
}
