package com.example.attacksimulator.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.attacksimulator.entity.AuthExperiments;

public interface AuthExperimentsRepository
extends JpaRepository<AuthExperiments, Long> {

	Optional<AuthExperiments> findByExperimentId(String experimentId);
}