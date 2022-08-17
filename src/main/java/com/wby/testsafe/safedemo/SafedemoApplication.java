package com.wby.testsafe.safedemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.util.logging.Logger;

@EnableJpaRepositories
@SpringBootApplication
public class SafedemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SafedemoApplication.class, args);
        System.out.println("启动成功");
    }

}
