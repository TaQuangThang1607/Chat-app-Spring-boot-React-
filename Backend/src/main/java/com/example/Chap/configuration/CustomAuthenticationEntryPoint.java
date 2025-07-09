package com.example.Chap.configuration;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.example.Chap.utils.RestResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint{
    private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint(); 
    private final ObjectMapper objectMapper;

    
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        RestResponse<Object> res = new RestResponse<>();
        res.setStatus(HttpStatus.UNAUTHORIZED.value());
        res.setError(authException.getMessage());
        res.setMessage("Authentication failed: Invalid or missing token");

        objectMapper.writeValue(response.getWriter(), res);
    }
    
    
}
