package com.example.jwt.domain.DTO;

import lombok.Data;

@Data
public class LoginDTO {
    private String memberId; // 아이디
    private String password; // 비밀번호
}