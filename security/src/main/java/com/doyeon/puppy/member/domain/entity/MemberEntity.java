package com.doyeon.puppy.member.domain.entity;

import com.doyeon.puppy.member.controller.request.JoinRequest;
import com.doyeon.puppy.member.enums.MemberRole;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
@Table(name = "members")
public class MemberEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email; // email  , 아이디

    private String nickname; // nickname

    private String password; // password , email회원 가입 때 사용 오어스 x

    @Enumerated(EnumType.STRING)
    private MemberRole role; // role

    public MemberEntity(String email, String nickname, String password, MemberRole memberRole) {
        this.email = email;
        this.nickname = nickname;
        this.password = password;
        this.role = memberRole;
    }

    public static MemberEntity of(JoinRequest joinRequest) {
        LocalDateTime now = LocalDateTime.now();
        return new MemberEntity(joinRequest.getEmail(), joinRequest.getNickname(),
                joinRequest.getPassword(), MemberRole.MEMBER);

    }

}
