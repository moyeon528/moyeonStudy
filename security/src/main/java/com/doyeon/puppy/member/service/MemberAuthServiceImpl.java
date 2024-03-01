package com.doyeon.puppy.member.service;

import com.doyeon.puppy.member.controller.request.JoinRequest;
import com.doyeon.puppy.member.controller.request.LoginRequest;
import com.doyeon.puppy.member.controller.response.JoinResponse;
import com.doyeon.puppy.member.controller.response.LoginResponse;
import com.doyeon.puppy.member.domain.entity.MemberEntity;
import com.doyeon.puppy.member.enums.MemberRole;
import com.doyeon.puppy.member.repository.MemberRepository;
import com.doyeon.puppy.security.TokenProvider;
import io.jsonwebtoken.Claims;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberAuthServiceImpl implements MemberAuthService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final TokenProvider tokenProvider;

    private final RedisTemplate<String, Object> redisTemplate;
//    private final WebClient kakaoClient;
//    private final WebClient kakaoApiClient;
//    private final Environment env;
    //    private final MyMailSender myMailSender;

    private static final String AUTHORITIES_KEY = "auth";
    private static final String TYPE = "Bearer ";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000L * 60 * 30;            // 30분

    @Override
    public JoinResponse join(JoinRequest joinRequest) {
        joinRequest.passwordEncoder(bCryptPasswordEncoder);
        Optional<MemberEntity> findMember = memberRepository.findByEmail(joinRequest.getEmail());
        if (findMember.isPresent()) {
            throw new IllegalArgumentException("이미 가입된 회원입니다.");
        }
        MemberEntity saveMemberEntity = memberRepository.save(MemberEntity.of(joinRequest));
//        myMailSender.send("puppy place와 함께 하게 된 것을 환영합니다 ~ ", "<html><h1>puppy place 회원가입이 완료되었습니다.</h1></html>",
//                saveMemberEntity.getEmail()); 어우 못하겠다 이거
        return JoinResponse.from(saveMemberEntity);
    }

    @Override
    public LoginResponse login(LoginRequest loginRequest) {
        // id, pw 기반으로 UsernamePasswordAuthenticationToken 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken = loginRequest.toAuthentication();

        // security에 구현한 AuthService가 실행됨
        Authentication authenticate = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);

        LoginResponse loginResponse = tokenProvider.generateTokenDto(authenticate);

        // token redis 저장
        saveRedisToken(loginResponse);

        return loginResponse;
    }

    @Override
    public LoginResponse refresh(String refreshToken) {

        if (!tokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        }

        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        String originAccessToken = Optional.ofNullable(ops.get(refreshToken)).orElse("").toString();
        Claims claims = tokenProvider.parseClaims(originAccessToken);

        String sub = claims.get("sub").toString();
        long now = (new Date()).getTime();
        Date accessTokenExpired = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);

        MemberEntity memberEntity = memberRepository.findById(Long.parseLong(sub)).orElseThrow(() ->
                new IllegalArgumentException("유효하지 않은 회원입니다.")
        );

        MemberRole memberRole = MemberRole.valueOf(memberEntity.getRole().roleName);
        String[] roleSplitList = memberRole.roleList.split(",");
        List<String> trimRoleList = Arrays.stream(roleSplitList)
                .map(r -> String.format("ROLE_%s", r.trim())).toList();
        String roleList = trimRoleList.toString().replace("[", "").replace("]", "")
                .replace(" ", "");

        String accessToken = tokenProvider.createAccessToken(String.valueOf(memberEntity.getId()),
                roleList, accessTokenExpired);

        Authentication authentication = tokenProvider.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return LoginResponse.builder()
                .type(TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpired(accessTokenExpired.getTime())
                .build();

    }

    private void saveRedisToken(LoginResponse loginResponse) {
        String accessToken = loginResponse.getAccessToken();
        String refreshToken = loginResponse.getRefreshToken();
        Claims claims = tokenProvider.parseClaims(refreshToken);
        long refreshTokenExpired = Long.parseLong(claims.get("exp").toString());

        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        ops.set(refreshToken, accessToken);
        redisTemplate.expireAt(refreshToken, new Date(refreshTokenExpired * 1000L));
    }

}
