package com.example.Chap.utils;

import java.time.Instant;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import com.example.Chap.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@RequiredArgsConstructor
public class ScheduledTasks {
    private static final Logger logger = LoggerFactory.getLogger(ScheduledTasks.class);
    private final UserRepository userRepository;

    @Scheduled(fixedRate = 3600000) // Chạy mỗi giờ
    public void cleanUpUnverifiedUsers() {
        logger.info("Running cleanup task for unverified users");
        userRepository.findAll().stream()
            .filter(user -> !user.isVerified() && user.getVerificationTokenExpiry() != null)
            .filter(user -> user.getVerificationTokenExpiry().isBefore(Instant.now()))
            .filter(user -> !user.isVerified() || user.getPassword() == null || user.getFullName() == null)
            .forEach(user -> {
                logger.info("Deleting unverified user: {}", user.getEmail());
                userRepository.delete(user);
            });
    }
}
