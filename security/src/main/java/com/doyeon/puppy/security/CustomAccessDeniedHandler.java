package com.doyeon.puppy.security;

import com.doyeon.puppy.base.ErrorDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {


    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        List<ErrorDto> errors = new ArrayList<>();
        errors.add(new ErrorDto("UNAUTHORIZED", "unauthorized token"));

//        ProblemDetail pb = ProblemDetail.forStatusAndDetail(
//                HttpStatusCode.valueOf(HttpStatus.SC_UNAUTHORIZED), "UNAUTHORIZED");
//        pb.setType(URI.create("/docs/index.html"));
//        pb.setProperty("errors", errors);
//        pb.setInstance(URI.create(request.getRequestURI()));
//        ObjectMapper objectMapper = new ObjectMapper();
//
//        PrintWriter writer = response.getWriter();
//        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        writer.write(objectMapper.writeValueAsString(pb));
    }
}
