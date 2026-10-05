package com.github.lechandonga.springbootiamservicejava.iam.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(IamProperties.class)
public class IamConfig {
}
