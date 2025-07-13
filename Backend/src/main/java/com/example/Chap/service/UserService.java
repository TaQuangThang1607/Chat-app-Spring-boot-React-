package com.example.Chap.service;

import java.time.Instant;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.Chap.model.Role;
import com.example.Chap.model.User;
import com.example.Chap.model.dto.UserDTO;
import com.example.Chap.repository.UserRepository;
import com.example.Chap.utils.exception.IdInvalidException;

import jakarta.mail.MessagingException;

@Service
public class UserService {
    private UserRepository userRepository;
    private EmailService emailService;
    private PasswordEncoder passwordEncoder;

    @Value("${verification.token-validity-in-minutes:5}") 
    private long verificationTokenValidityHours;

    public UserService(UserRepository userRepository,EmailService emailService,
    PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.emailService=emailService;
        this.passwordEncoder=passwordEncoder;
    }

    public Optional<User> handleGetUserByEmail(String email){
        return userRepository.findByEmail(email);
    }

    public void updateUserToken(String token, String email){
        Optional<User> curremtUser = this.handleGetUserByEmail(email);
        if(curremtUser.isPresent()){
            User user = curremtUser.get();
            user.setRefreshToken(token);
            this.userRepository.save(user);
        }
    }

    public boolean isEmailExist(String email) {
        return this.userRepository.existsByEmail(email);
    }

    // public UserDTO createUser(UserDTO dto) {
    //     User user = new User();
    //     user.setEmail(dto.getEmail());
    //     user.setPassword(dto.getPassword());
    //     user.setFullName(dto.getFullName());

    //     // Nếu ROLE không được cung cấp thì mặc định là USER
    //     user.setRole(dto.getRole() != null ? dto.getRole() : Role.USER);
        
    //     // Kiểm tra quyền nếu muốn gán role khác USER (tùy chọn)
    //     if (dto.getRole() != null && dto.getRole() != Role.USER) {
    //         if (!SecurityUtil.hasCurrentUserThisAuthority("ADMIN")) {
    //             throw new SecurityException("Only ADMIN can assign roles other than USER");
    //         }
    //     }

    //     user = userRepository.save(user);

    //     UserDTO userDTO = new UserDTO();
    //     userDTO.setId(user.getId());
    //     userDTO.setEmail(user.getEmail());
    //     userDTO.setFullName(user.getFullName());

    //     return userDTO;
    // }
    // send mail with token
    public UserDTO initiateRegistration(UserDTO dto) throws IdInvalidException, MessagingException{
        if(this.userRepository.existsByEmail(dto.getEmail())){
            throw new IdInvalidException("Email " + dto.getEmail()+" already exists");
        }
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setRole(Role.USER);
        String verificationEmailToken = emailService.sendVerificationEmail(dto.getEmail());
        user.setVerificationToken(verificationEmailToken);
        user.setVerified(false);
        user.setVerificationTokenExpiry(Instant.now().plusSeconds(verificationTokenValidityHours * 60)); // hết hạn sau 24h
        userRepository.save(user);

        UserDTO userDTO = new UserDTO();
        userDTO.setEmail(dto.getEmail());

        return userDTO;
    }
    // Verify token before allowing password change
    public User verifyEmail(String token) throws IdInvalidException{
        User user = userRepository.findByVerificationToken(token)
        .orElseThrow(() -> new IdInvalidException("Invalid verificatioon Token"));
        
        if(user.isVerified()){
            throw new IdInvalidException("Email already exists");
        }
        user.setVerified(true);
        user.setVerificationTokenExpiry(Instant.now().plusSeconds(verificationTokenValidityHours * 60));
        return this.userRepository.save(user);
    }

    public UserDTO completeRegistration(UserDTO dto, String token) throws IdInvalidException{
        User user = this.userRepository.findByVerificationToken(token)
        .orElseThrow(() -> new IdInvalidException("Invalid verification token"));
        
        if(!user.isVerified()){
            throw new IdInvalidException("Email not verified");
        }
        if (user.getVerificationTokenExpiry().isBefore(Instant.now())) {
            userRepository.delete(user); //xóa nếu token hết hạn
            throw new IdInvalidException("Verification token expired");
        }

        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setFullName(dto.getFullName());

        user.setVerificationToken(null);
        user.setVerificationTokenExpiry(null);

        user = userRepository.save(user);

        UserDTO userDTO = new UserDTO();
        userDTO.setEmail(user.getEmail());
        userDTO.setFullName(user.getFullName());
        userDTO.setRole(Role.USER);
        return userDTO;
    }

}
