package gdsc.skhu.jwtskhu.domain.DTO;


import lombok.Data;

@Data
public class LoginDTO {
    private String memberId;
    private String password;
}