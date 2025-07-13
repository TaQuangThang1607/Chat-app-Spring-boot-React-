package com.example.Chap.configuration;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DotEnvConfig {
    @Bean
    public Dotenv dotenv() {
        return Dotenv.configure().load();
    }
}