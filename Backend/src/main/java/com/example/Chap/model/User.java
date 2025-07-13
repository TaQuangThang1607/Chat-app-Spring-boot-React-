package com.example.Chap.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String email;
    private String password;

    private String fullName;
    
    @Enumerated(EnumType.STRING) // LỮU DƯỚI DẠNG CHUỖI
    @Column(nullable = false)
    private Role role = Role.USER;

    @Column(columnDefinition = "MEDIUMTEXT")
    private String refreshToken;

    @Column(columnDefinition = "MEDIUMTEXT")
    private String resetPasswordToken;

    @Column
    private Instant resetPasswordTokenExpiry;
    

    @Column(columnDefinition = "MEDIUMTEXT")
    private String verificationToken;

    @Column
    private Instant verificationTokenExpiry;

    @Column(nullable = false)
    private boolean isVerified = false;


}
