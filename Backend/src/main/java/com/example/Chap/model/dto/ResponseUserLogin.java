package com.example.Chap.model.dto;

import lombok.NoArgsConstructor;

import com.example.Chap.model.Role;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResponseUserLogin {

    @JsonProperty("access_token")
    private String accessToken;
    private UserLogin userLogin;
    

    @Data
    @AllArgsConstructor
    public static class UserLogin{
        private Long id;
        private String email;
        private String fullName;
        private Role role;
    }
}
