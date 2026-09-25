package com.example.attacksimulator.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.attacksimulator.model.ExperimentResult;

public interface ExperimentResultRepository
        extends JpaRepository<ExperimentResult, Long> {

    // =========================================================
    // ID（実験番号）の昇順
    // =========================================================

    List<ExperimentResult>
    findAllByOrderByIdAsc();

    // =========================================================
    // 認証方式ごとの結果
    // ID（実験番号）の昇順
    // =========================================================

    List<ExperimentResult>
    findByAuthMethodOrderByIdAsc(
            String authMethod);

    // =========================================================
    // 指定したIDより大きい結果を取得
    // =========================================================

    List<ExperimentResult>
    findByIdGreaterThanOrderByIdAsc(
            Long id);

    // =========================================================
    // 最新の実験結果
    // IDが最大のもの
    // =========================================================

    Optional<ExperimentResult>
    findTopByOrderByIdDesc();
}