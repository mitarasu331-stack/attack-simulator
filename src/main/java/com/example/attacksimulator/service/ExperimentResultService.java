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

    // ========================================
    // 保存
    // ========================================

    /**
     * ExperimentResultオブジェクトをDBに保存
     */
    public ExperimentResult addResult(
            ExperimentResult result) {

        /*
         * 実験番号が設定されていない場合は
         * 次の実験番号を自動設定
         */
        if (result.getExperimentNumber() <= 0) {

            result.setExperimentNumber(
                    getNextExperimentNumber());
        }

        return experimentResultRepository.save(
                result);
    }

    /**
     * 各項目を指定して実験結果を作成し、
     * DBに保存する
     *
     * AttackControllerから使用
     */
    public ExperimentResult addResult(
            int experimentNumber,
            String authMethod,
            int operationCount,
            String authenticationConfiguration,
            int maxAttemptCount,
            int attemptCount,
            boolean success,
            String credential,
            long attackTimeMs) {

        ExperimentResult result =
                new ExperimentResult();

        result.setExperimentNumber(
                experimentNumber);

        result.setAuthMethod(
                authMethod);

        result.setOperationCount(
                operationCount);

        result.setAuthenticationConfiguration(
                authenticationConfiguration);

        result.setMaxAttemptCount(
                maxAttemptCount);

        result.setAttemptCount(
                attemptCount);

        result.setSuccess(
                success);

        result.setCredential(
                credential);

        result.setAttackTimeMs(
                attackTimeMs);
        
        result.setExperimentDateTime(
                java.time.LocalDateTime.now());

        return experimentResultRepository.save(
                result);
    }

    /**
     * 次の実験番号を取得
     */
    public int getNextExperimentNumber() {

        List<ExperimentResult> results =
                experimentResultRepository
                        .findAllByOrderByExperimentNumberAsc();

        if (results.isEmpty()) {
            return 1;
        }

        return results.get(results.size() - 1)
                .getExperimentNumber() + 1;
    }

    // ========================================
    // 取得
    // ========================================

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
     * AttackControllerとの互換用
     *
     * 全実験結果を取得
     */
    public List<ExperimentResult> getAllResults() {

        return getResults();
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

    // ========================================
    // 件数
    // ========================================

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

    // ========================================
    // 認証突破率
    // ========================================

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

    // ========================================
    // 攻撃試行回数
    // ========================================

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

    // ========================================
    // 攻撃時間
    // ========================================

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
     * AttackControllerとの互換用
     */
    @Transactional
    public void deleteResults(
            List<Long> ids) {

        deleteResultsByIds(ids);
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