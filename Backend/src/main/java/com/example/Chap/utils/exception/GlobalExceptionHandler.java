package com.example.Chap.utils.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import com.example.Chap.utils.RestResponse;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler {

    // Xử lý lỗi validation
    @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
    public ResponseEntity<RestResponse<Object>> handleValidationException(Exception ex) {
        String errorMessage = ex instanceof MethodArgumentNotValidException
                ? ((MethodArgumentNotValidException) ex).getBindingResult().getAllErrors()
                        .stream()
                        .map(e -> e.getDefaultMessage())
                        .collect(Collectors.joining("; "))
                : ex.getMessage();

        RestResponse<Object> response = new RestResponse<>();
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setError("Validation failed");
        response.setMessage(errorMessage);
        return ResponseEntity.badRequest().body(response);
    }

    // Xử lý IdInvalidException
    @ExceptionHandler(IdInvalidException.class)
    public ResponseEntity<RestResponse<Object>> handleIdInvalidException(IdInvalidException ex) {
        RestResponse<Object> response = new RestResponse<>();
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setError("Invalid input");
        response.setMessage(ex.getMessage());
        return ResponseEntity.badRequest().body(response);
    }

    // Xử lý các lỗi chung
    @ExceptionHandler(Exception.class)
    public ResponseEntity<RestResponse<Object>> handleGeneralException(Exception ex) {
        RestResponse<Object> response = new RestResponse<>();
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setError("Server error");
        response.setMessage(ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}