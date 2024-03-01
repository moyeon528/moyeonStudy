package com.doyeon.puppy.member.controller.response;

import com.doyeon.puppy.member.domain.entity.MemberEntity;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@Getter
@AllArgsConstructor
@Builder
public class JoinResponse {

    private String name;
    private String nickname;
    private String email;

    public static JoinResponse from(MemberEntity saveMemberEntity) {
        return JoinResponse.builder()
                .email(saveMemberEntity.getEmail())
                .nickname(saveMemberEntity.getNickname())
                .build();
    }
}
