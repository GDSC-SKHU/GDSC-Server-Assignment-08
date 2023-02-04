package com.gdsc.jwtexample.domain.DTO;

import lombok.Data;

@Data
public class LoginDTO {
    private String memberId; // 회원 ID
    private String password; // 비밀번호
}
