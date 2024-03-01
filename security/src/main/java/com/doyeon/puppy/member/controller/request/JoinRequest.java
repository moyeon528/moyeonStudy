package com.doyeon.puppy.member.controller.request;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JoinRequest {

    @Email(message = "이메일 형식이 아닙니다.", regexp = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")
    @NotNull(message = "이메일을 입력해주세요.") // 얘네 사용하나요 ?
    private String email;
    @NotNull(message = "비밀번호를 입력해주세요.")
    private String password;
    @NotNull(message = "닉네임을 입력해주세요.")
    private String nickname;

    public void passwordEncoder(BCryptPasswordEncoder encoder) {
        this.password = encoder.encode(this.password);
    }
}
