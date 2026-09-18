package com.example.attacksimulator.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.attacksimulator.model.ExperimentResult;
import com.example.attacksimulator.repository.ExperimentResultRepository;

@Service
public class ExperimentResultService {

    private final ExperimentResultRepository
            experimentResultRepository;

    public ExperimentResultService(
            ExperimentResultRepository
                    experimentResultRepository) {

        this.experimentResultRepository =
                experimentResultRepository;
    }

    /**
     * 実験結果をDBに保存
     */
    public ExperimentResult addResult(
            ExperimentResult result) {

        /*
         * 実験番号を自動設定
         */
        if (result.getExperimentNumber() <= 0) {

            int nextExperimentNumber =
                    getResultCount() + 1;

            result.setExperimentNumber(
                    nextExperimentNumber);
        }

        return experimentResultRepository.save(
                result);
    }

    /**
     * 全実験結果を取得
     *
     * 実験番号の昇順
     */
    public List<ExperimentResult> getResults() {

        return experimentResultRepository
                .findAllByOrderByExperimentNumberAsc();
    }

    /**
     * 認証方式ごとの実験結果を取得
     */
    public List<ExperimentResult>
    getResultsByAuthMethod(
            String authMethod) {

        return experimentResultRepository
                .findByAuthMethodOrderByExperimentNumberAsc(
                        authMethod);
    }

    /**
     * 実験結果の総数
     */
    public int getResultCount() {

        return (int)
                experimentResultRepository.count();
    }

    /**
     * 認証方式ごとの実験回数
     */
    public int getExperimentCountByAuthMethod(
            String authMethod) {

        return getResultsByAuthMethod(
                authMethod).size();
    }

    /**
     * 認証方式ごとの成功回数
     */
    public int getSuccessCountByAuthMethod(
            String authMethod) {

        int successCount = 0;

        for (ExperimentResult result :
                getResultsByAuthMethod(authMethod)) {

            if (result.isSuccess()) {
                successCount++;
            }
        }

        return successCount;
    }

    /**
     * 認証方式ごとの認証突破率
     */
    public double getSuccessRateByAuthMethod(
            String authMethod) {

        int totalExperimentCount =
                getExperimentCountByAuthMethod(
                        authMethod);

        if (totalExperimentCount == 0) {
            return 0.0;
        }

        int successCount =
                getSuccessCountByAuthMethod(
                        authMethod);

        return (double) successCount
                / totalExperimentCount
                * 100.0;
    }

    /**
     * 認証方式ごとの平均攻撃試行回数
     */
    public double getAverageAttemptCountByAuthMethod(
            String authMethod) {

        List<ExperimentResult> results =
                getResultsByAuthMethod(
                        authMethod);

        if (results.isEmpty()) {
            return 0.0;
        }

        long totalAttemptCount = 0;

        for (ExperimentResult result : results) {

            totalAttemptCount +=
                    result.getAttemptCount();
        }

        return (double) totalAttemptCount
                / results.size();
    }

    /**
     * 認証方式ごとの
     * 成功時の攻撃時間の合計
     */
    public long getSuccessAttackTimeTotalByAuthMethod(
            String authMethod) {

        long totalTime = 0;

        for (ExperimentResult result :
                getResultsByAuthMethod(authMethod)) {

            if (result.isSuccess()) {

                totalTime +=
                        result.getAttackTimeMs();
            }
        }

        return totalTime;
    }

    /**
     * 認証方式ごとの
     * 平均攻撃成功時間
     */
    public double getAverageSuccessAttackTimeByAuthMethod(
            String authMethod) {

        int successCount =
                getSuccessCountByAuthMethod(
                        authMethod);

        if (successCount == 0) {
            return 0.0;
        }

        return (double)
                getSuccessAttackTimeTotalByAuthMethod(
                        authMethod)
                / successCount;
    }

    // ========================================
    // 全体集計
    // ========================================

    /**
     * 全実験回数
     */
    public int getTotalExperimentCount() {

        return getResultCount();
    }

    /**
     * 全成功回数
     */
    public int getSuccessCount() {

        int successCount = 0;

        for (ExperimentResult result :
                getResults()) {

            if (result.isSuccess()) {
                successCount++;
            }
        }

        return successCount;
    }

    /**
     * 全体の認証突破率
     */
    public double getSuccessRate() {

        int totalExperimentCount =
                getTotalExperimentCount();

        if (totalExperimentCount == 0) {
            return 0.0;
        }

        return (double) getSuccessCount()
                / totalExperimentCount
                * 100.0;
    }

    /**
     * 全体の平均攻撃試行回数
     */
    public double getAverageAttemptCount() {

        List<ExperimentResult> results =
                getResults();

        if (results.isEmpty()) {
            return 0.0;
        }

        long totalAttemptCount = 0;

        for (ExperimentResult result : results) {

            totalAttemptCount +=
                    result.getAttemptCount();
        }

        return (double) totalAttemptCount
                / results.size();
    }

    /**
     * 全体の成功時の攻撃時間の合計
     */
    public long getSuccessAttackTimeTotal() {

        long totalTime = 0;

        for (ExperimentResult result :
                getResults()) {

            if (result.isSuccess()) {

                totalTime +=
                        result.getAttackTimeMs();
            }
        }

        return totalTime;
    }

    /**
     * 全体の平均攻撃成功時間
     */
    public double getAverageSuccessAttackTime() {

        int successCount =
                getSuccessCount();

        if (successCount == 0) {
            return 0.0;
        }

        return (double)
                getSuccessAttackTimeTotal()
                / successCount;
    }

    // ========================================
    // 削除処理
    // ========================================

    /**
     * 指定したIDの実験結果を複数削除する
     */
    @Transactional
    public void deleteResultsByIds(
            List<Long> ids) {

        if (ids == null || ids.isEmpty()) {
            return;
        }

        experimentResultRepository.deleteAllById(
                ids);

        /*
         * 削除後に実験番号を1から詰め直す
         */
        renumberExperiments();
    }

    /**
     * 全実験結果を削除する
     */
    @Transactional
    public void clearResults() {

        experimentResultRepository.deleteAll();
    }

    /**
     * 実験番号を1から振り直す
     */
    @Transactional
    public void renumberExperiments() {

        List<ExperimentResult> results =
                experimentResultRepository
                        .findAllByOrderByExperimentNumberAsc();

        int experimentNumber = 1;

        for (ExperimentResult result : results) {

            result.setExperimentNumber(
                    experimentNumber);

            experimentNumber++;
        }

        experimentResultRepository.saveAll(
                results);
    }
}