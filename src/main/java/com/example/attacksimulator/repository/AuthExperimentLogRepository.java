package com.example.attacksimulator.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.attacksimulator.entity.AuthExperimentLog;

public interface AuthExperimentLogRepository
extends JpaRepository<AuthExperimentLog, Long> {

	List<AuthExperimentLog> findByExperimentIdOrderByAttemptNumberAsc(
			String experimentId);
}