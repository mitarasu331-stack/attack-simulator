package com.example.attacksimulator.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.attacksimulator.model.ExperimentResult;

@Repository
public interface ExperimentResultRepository
        extends JpaRepository<ExperimentResult, Long> {

    /**
     * 実験番号の昇順で全実験結果を取得
     */
    List<ExperimentResult>
    findAllByOrderByExperimentNumberAsc();

    /**
     * 認証方式ごとの実験結果を
     * 実験番号の昇順で取得
     */
    List<ExperimentResult>
    findByAuthMethodOrderByExperimentNumberAsc(
            String authMethod);

    /**
     * 指定した実験番号より大きい番号の
     * 実験結果を取得
     */
    List<ExperimentResult>
    findByExperimentNumberGreaterThanOrderByExperimentNumberAsc(
            int experimentNumber);
    
    Optional<ExperimentResult>
    findTopByOrderByExperimentNumberDesc();
}