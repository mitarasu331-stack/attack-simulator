package com.example.attacksimulator.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@Configuration
public class NewAuthLabJdbcConfig {

    @Value("${newauthlab.datasource.url}")
    private String url;

    @Value("${newauthlab.datasource.username}")
    private String username;

    @Value("${newauthlab.datasource.password}")
    private String password;

    @Value("${newauthlab.datasource.driver-class-name}")
    private String driverClassName;

    @Bean(name = "newAuthLabJdbcTemplate")
    public JdbcTemplate newAuthLabJdbcTemplate() {

        DriverManagerDataSource dataSource =
                new DriverManagerDataSource();

        dataSource.setDriverClassName(driverClassName);
        dataSource.setUrl(url);
        dataSource.setUsername(username);
        dataSource.setPassword(password);

        return new JdbcTemplate(dataSource);
    }
}