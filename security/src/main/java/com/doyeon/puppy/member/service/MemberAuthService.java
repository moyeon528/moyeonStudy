package com.doyeon.puppy.member.service;

import com.doyeon.puppy.member.controller.request.JoinRequest;
import com.doyeon.puppy.member.controller.request.LoginRequest;
import com.doyeon.puppy.member.controller.response.JoinResponse;
import com.doyeon.puppy.member.controller.response.LoginResponse;

public interface MemberAuthService {

    JoinResponse join(JoinRequest joinRequest);

    LoginResponse login(LoginRequest loginRequest);

    LoginResponse refresh(String refreshToken);
//    LoginResponse authKaKao(String accessToken); // 카카오 로그인
//    LoginResponse loinKaKao(String accessToken);

}
