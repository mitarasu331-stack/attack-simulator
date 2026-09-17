package com.example.attacksimulator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import service.AttackSimulatorService;

@SpringBootApplication
public class AttacksimulatorApplication {

	public static void main(String[] args) {
		SpringApplication.run(AttacksimulatorApplication.class, args);
		AttackSimulatorService simulator = new AttackSimulatorService();
		simulator.start();
	}

	
}
