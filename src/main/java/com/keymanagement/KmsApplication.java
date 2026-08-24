package com.keymanagement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class KmsApplication {

    private static final Logger log = LoggerFactory.getLogger(KmsApplication.class);

    public static void main(String[] args) {
        log.info("Starting Key Management Service (KMS) Application...");
        SpringApplication.run(KmsApplication.class, args);
        log.info("Key Management Service (KMS) Application started successfully");
    }

}
