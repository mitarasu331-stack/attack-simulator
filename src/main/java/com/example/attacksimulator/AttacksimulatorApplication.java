package com.example.attacksimulator;

import java.io.IOException;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import service.AttackSimulatorService;

@SpringBootApplication
public class AttacksimulatorApplication {

    public static void main(String[] args) throws IOException {
        SpringApplication.run(AttacksimulatorApplication.class, args);

        AttackSimulatorService simulator = new AttackSimulatorService();
        simulator.start();
    }

}