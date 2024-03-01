package com.doyeon.puppy.security;

import com.doyeon.puppy.base.ErrorDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
//import org.springframework.http.HttpStatus;

@Component
public class CustomEntryPoint implements AuthenticationEntryPoint {

//    @Value("${docs}")
//    private String docs;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        List<ErrorDto> errors = new ArrayList<>();
        String requestURI = request.getRequestURI();

        if (requestURI.contains("/login")) {
            errors.add(new ErrorDto("email / password", "이메일 or 비밀번호가 틀렸습니다."));
        } else {
            errors.add(new ErrorDto("access token", "권한이 없습니다."));
        }

//        ProblemDetail pb = ProblemDetail.forStatusAndDetail(
//                HttpStatusCode.valueOf(HttpStatus.FORBIDDEN), "FORBIDDEN");
//        pb.setType(URI.create(docs));
//        pb.setProperty("errors", errors);
//        pb.setInstance(URI.create(requestURI));
//        ObjectMapper objectMapper = new ObjectMapper();

        PrintWriter writer = response.getWriter();
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        writer.write(objectMapper.writeValueAsString(pb));
    }
}
