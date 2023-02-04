package gdsc.skhu.jwtskhu.domain.dto;

import lombok.Data;

@Data
public class LoginDTO {
    private String memberId;
    private String password;
}