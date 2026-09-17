package com.example.attacksimulator.service;

import java.math.BigDecimal;
import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.entity.AuthExperiment;
import com.example.attacksimulator.repository.AuthExperimentRepository;

@Service
public class ExperimentService {

    private final AuthExperimentRepository authExperimentRepository;

    public ExperimentService(
            AuthExperimentRepository authExperimentRepository) {

        this.authExperimentRepository = authExperimentRepository;
    }

    /**
     * 実験結果を保存する
     */
    public AuthExperiment saveExperiment(
            String experimentId,
            String authMethod,
            int authCount,
            String authType,
            String attackType,
            int totalCount,
            int successCount,
            BigDecimal totalDurationMs) {

        AuthExperiment experiment = new AuthExperiment();

        experiment.setExperimentId(experimentId);
        experiment.setAuthMethod(authMethod);
        experiment.setAuthCount(authCount);
        experiment.setAuthType(authType);
        experiment.setAttackType(attackType);
        experiment.setTotalCount(totalCount);
        experiment.setSuccessCount(successCount);
        experiment.setTotalDurationMs(totalDurationMs);
        experiment.setAuthTime(LocalDateTime.now());

        return authExperimentRepository.save(experiment);
    }

    /**
     * 実験IDから実験結果を取得する
     */
    public AuthExperiment findExperiment(
            String experimentId) {

        return authExperimentRepository
                .findByExperimentId(experimentId)
                .orElse(null);
    }
}