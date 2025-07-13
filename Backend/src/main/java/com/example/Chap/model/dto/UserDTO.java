package com.example.Chap.model.dto;

import com.example.Chap.model.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Long id;
    
    @Email(message = "Invalid email")
    @NotNull(message = "Email is required")
    private String email;

    @Size(min = 8, max =8, message = "Password must be exactly 8 characters")
    private String password;
    
    private String fullName;

    private Role role;

}
