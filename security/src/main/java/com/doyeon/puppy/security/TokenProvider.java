package com.doyeon.puppy.security;

//import static org.springframework.http.HttpHeaders.AUTHORIZATION;

//import jakarta.servlet.http.HttpServletRequest;
//import org.springframework.util.StringUtils;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.doyeon.puppy.member.controller.response.LoginResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
public class TokenProvider {

    private static final String AUTHORITIES_KEY = "auth";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000L * 60 * 30; // 30분
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000L * 60 * 60 * 24 * 7; // 7일

    private static final String TYPE = "Bearer";
    private final Key key;

    @Value("${spring.profiles.active}")
    private String profile;

    public TokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public LoginResponse generateTokenDto(Authentication authentication) {
        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining());

        long now = (new Date()).getTime();

        // Access Token 생성
        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);
        String accessToken = createAccessToken(authentication.getName(), authorities,
                accessTokenExpiresIn);

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + REFRESH_TOKEN_EXPIRE_TIME))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return LoginResponse.builder()
                .type(TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpired(accessTokenExpiresIn.getTime())
                .build();

    }

    public String createAccessToken(String sub, String authorities, Date accessTokenExpiresIn) {
        // Access Token 생성
        return Jwts.builder()
                .setSubject(sub) // payload "sub" : "name"
                .claim(AUTHORITIES_KEY, authorities) // payload "auth" : "ROLE_USER"
                .setExpiration(accessTokenExpiresIn) // payload "exp" : "expireTime" 1516239022 (예시)
                .signWith(key, SignatureAlgorithm.HS512) // header "alg" : "HS512"
                .compact();
    }

    public Authentication getAuthentication(String accessToken) {
        // 토큰을 파싱해서 Authentication 객체를 만들어서 리턴 복구화
        Claims claims = parseClaims(accessToken);

        if (claims.get(AUTHORITIES_KEY) == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }
        // 권한 정보를 가져옴 (클레임)
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .toList();
        // User 객체를 만들어서 Authentication 객체를 리턴
        UserDetails principal = new User(claims.getSubject(), "",
                authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities); // 가운데 토큰 안 넣어 ?
    }

    public boolean validateToken(String token) {
        // 토큰 유효성 검사
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.warn("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.warn("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.warn("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    public Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

//     test ?
//    ------------------------------

    public Long getMemberId(String token) {
        if (profile.equals("local") && token.contains("test")) {
            return getTestMemberId(token);
        }

        Claims claims = parseClaims(token);
        return Long.parseLong(claims.get("sub").toString());
    }

    private static Long getTestMemberId(String token) {
        Map<String, Long> memberMap = new HashMap<>();
        memberMap.put("member-test-token", 1L);
        memberMap.put("seller-test-token", 2L);
        memberMap.put("seller2-test-token", 3L);

        return memberMap.get(token);
    }

    public Long getMemberId(HttpServletRequest request) {
        String token = resolveToken(request);

        if (profile.equals("local") && token.contains("test")) {
            return getTestMemberId(token);
        }
        return getMemberId(token);
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TYPE)) {
            return bearerToken.substring(TYPE.length());
        }
        return null;
    }

}
