package com.example.Chap.service;

import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);
    private final JavaMailSender mailSender;
    private final String fromEmail;
    private final String baseUrl;

    public EmailService(JavaMailSender mailSender,
                       @Value("${MAIL_FROM}") String fromEmail,
                       @Value("${app.base-url}") String baseUrl) {
        this.mailSender = mailSender;
        this.fromEmail = fromEmail;
        this.baseUrl = baseUrl;
    }

    public String sendVerificationEmail(String toEmail) throws MessagingException {
        String token = UUID.randomUUID().toString();
        String verificationLink = baseUrl + "/api/v1/auth/verify?token=" + token;

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setFrom(fromEmail);
        helper.setTo(toEmail);
        helper.setSubject("Verify Your Email Address");
        helper.setText(
            "<h1>Email Verification</h1>" +
            "<p>Please click the link below to verify your email:</p>" +
            "<a href=\"" + verificationLink + "\">Verify Email</a>",
            "<p> Confirmed in 5 minutes </p>"
        );

        mailSender.send(message);
        logger.info("Verification email sent to: {}", toEmail);
        return token;
    }
}
