package com.doyeon.puppy.security;


import com.doyeon.puppy.member.enums.MemberRole;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotNull;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final CustomEntryPoint entryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;

    private static final String[] ADMIN_LIST = {
            "/api/admin/**",  // 다시 세팅하기
    };
    private static final String[] MEMBER_LIST = {
            "/api/member/**",  // 다시 세팅하기
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        JwtSecurityConfig jwtSecurityConfig = new JwtSecurityConfig(tokenProvider);
        http
//                .csrf(c -> c.disable()) // rest api csrf 보안 필요 없음
                .csrf(AbstractHttpConfigurer::disable)
                .cors(c -> c.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(
                            @NotNull HttpServletRequest request) { // NotNull 추가
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOriginPatterns(Collections.singletonList("*"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(600L);
                        return config;
                    }
                }))
                .exceptionHandling(c ->
                        c.authenticationEntryPoint(entryPoint)
                                .accessDeniedHandler(accessDeniedHandler))
                .headers(c -> c.frameOptions(FrameOptionsConfig::disable)
                        .disable()) // h2-console 사용하기 위해 , 람다로 변경
                .authorizeHttpRequests(auth ->
                        auth
                                .requestMatchers(PathRequest.toH2Console()).permitAll()
                                .requestMatchers(ADMIN_LIST).hasRole(MemberRole.ADMIN.roleName)
                                .requestMatchers(MEMBER_LIST).hasRole(MemberRole.MEMBER.roleName)
                                .anyRequest().permitAll())
                .sessionManagement(
                        c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 사용 안 함
                .addFilterBefore((Filter) new JwtSecurityConfig(tokenProvider),
                        UsernamePasswordAuthenticationFilter.class);
//                        (Class<? extends Filter>) AuthFilter.class); // JwtSecurity  적용
//                .apply(jwtSecurityConfig); // 왜 안되냐고 시불 ..
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

