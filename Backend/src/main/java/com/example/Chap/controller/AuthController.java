package com.example.Chap.controller;

import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.Chap.model.User;
import com.example.Chap.model.dto.ResponseUserLogin;
import com.example.Chap.model.dto.UserDTO;
import com.example.Chap.service.UserService;
import com.example.Chap.utils.RestResponse;
import com.example.Chap.utils.SecurityUtil;
import com.example.Chap.utils.exception.IdInvalidException;

import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UserService userService;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final  SecurityUtil securityUtil;

    @Value("${jwt.refresh.token-validity-in-seconds}")
    private long refreshTokenExpiration;
    
    

    @PostMapping("/login")
    public ResponseEntity<ResponseUserLogin> login(@RequestBody UserDTO dto) throws IdInvalidException {
        Optional<User> currentUser = userService.handleGetUserByEmail(dto.getEmail());
        if(!currentUser.isPresent()){
            throw new UsernameNotFoundException("email not found" + dto.getEmail());
        }
        try {
           UsernamePasswordAuthenticationToken authenticationToken = 
                    new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword());
            Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            ResponseUserLogin loginUser = new ResponseUserLogin();
            User user = currentUser.get();
            ResponseUserLogin.UserLogin userLogin = new ResponseUserLogin.UserLogin(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getRole()
            );
            loginUser.setUserLogin(userLogin);

            String accessToken = securityUtil.createAccessToken(authentication.getName(), loginUser.getUserLogin());
            String refreshToken = securityUtil.createRefreshToken(dto.getEmail(), loginUser);

            loginUser.setAccessToken(accessToken);
            userService.updateUserToken(refreshToken, dto.getEmail());

            ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken",accessToken)
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(3600)
            .build();

            ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(refreshTokenExpiration)
            .build();

            return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString(), refreshTokenCookie.toString())
            .body(loginUser);

        } catch (BadCredentialsException  e) {
            // TODO: handle exception
            throw new IdInvalidException("Password is incorrect");
        } catch (Exception e) {
            throw new IdInvalidException("Something went wrong while logging in " + e.getMessage());
        }

    }

    @PostMapping("/register")
    public ResponseEntity<RestResponse<Object>> initiateRegistration(@Valid @RequestBody UserDTO dto) throws IdInvalidException, MessagingException {

        try {
            UserDTO userDTO = userService.initiateRegistration(dto);
            RestResponse<Object> response = new RestResponse<>();
            response.setStatus(HttpStatus.OK.value());
            response.setData(userDTO);
            response.setMessage("Verification email sent successfully");
            return ResponseEntity.ok().body(response);
        } catch (Exception e) {
            RestResponse<Object> response = new RestResponse<>();
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setError(e.getMessage());
            response.setMessage("Failed to initiate registration");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<RestResponse<Object>> verifyEmail(@RequestParam("token") String token) throws IdInvalidException {
        try {
            User user = userService.verifyEmail(token);
            RestResponse<Object> response = new RestResponse<>();
            response.setStatus(HttpStatus.OK.value());
            response.setMessage("Email verified successfully. Please complete registration.");
            response.setData(new UserDTO(user.getId(), user.getEmail(), null, null, null));
            return ResponseEntity.ok().body(response);
        } catch (IdInvalidException e) {
            RestResponse<Object> response = new RestResponse<>();
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.setError(e.getMessage());
            response.setMessage("Email verification failed");
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/complete-registration")
    public ResponseEntity<RestResponse<Object>> completeRegistration(@Valid @RequestBody UserDTO dto, @RequestParam("token") String token, BindingResult bindingResult) throws IdInvalidException {
        if (bindingResult.hasFieldErrors("password") || bindingResult.hasFieldErrors("fullName")) {
            RestResponse<Object> response = new RestResponse<>();
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.setError("Validation failed");
            response.setMessage(bindingResult.getAllErrors()
                    .stream()
                    .map(e -> e.getDefaultMessage())
                    .collect(Collectors.joining("; ")));
            return ResponseEntity.badRequest().body(response);
        }

        try {
            UserDTO userDTO = userService.completeRegistration(dto, token);
            RestResponse<Object> response = new RestResponse<>();
            response.setStatus(HttpStatus.CREATED.value());
            response.setData(userDTO);
            response.setMessage("User registered successfully");
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            RestResponse<Object> response = new RestResponse<>();
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setError(e.getMessage());
            response.setMessage("Failed to complete registration");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

}
