package com.doyeon.puppy.member.controller;

import com.doyeon.puppy.member.service.MemberAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api-prefix}/auth")
@RequiredArgsConstructor
public class AuthController {

    private final MemberAuthService memberAuthService;

}
