package com.gdsc.jwtpractice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication
public class JwtPracticeApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtPracticeApplication.class, args);
    }

}
