package com.example.attacksimulator.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.attacksimulator.entity.AuthExperiment;

public interface AuthExperimentRepository
extends JpaRepository<AuthExperiment, Long> {

	Optional<AuthExperiment> findByExperimentId(String experimentId);
}