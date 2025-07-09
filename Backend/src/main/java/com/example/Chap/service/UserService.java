package com.example.Chap.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.example.Chap.model.Role;
import com.example.Chap.model.User;
import com.example.Chap.model.dto.UserDTO;
import com.example.Chap.repository.UserRepository;
import com.example.Chap.utils.SecurityUtil;

import jakarta.validation.Valid;

@Service
public class UserService {
    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
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

    public UserDTO createUser(UserDTO dto) {
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword(dto.getPassword());
        user.setFullName(dto.getFullName());


        // Nếu ROLE không được cung cấp thì mặc định là USER
        user.setRole(dto.getRole() != null ? dto.getRole() : Role.USER);
        
        // Kiểm tra quyền nếu muốn gán role khác USER (tùy chọn)
        if (dto.getRole() != null && dto.getRole() != Role.USER) {
            if (!SecurityUtil.hasCurrentUserThisAuthority("ADMIN")) {
                throw new SecurityException("Only ADMIN can assign roles other than USER");
            }
        }


        user = userRepository.save(user);

        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setEmail(user.getEmail());
        userDTO.setFullName(user.getFullName());

        return userDTO;
    }
}
