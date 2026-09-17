package com.example.attacksimulator.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.model.ExperimentResult;

@Service
public class ExperimentResultService {

    private final List<ExperimentResult> results =
            new ArrayList<>();

    /**
     * 実験結果を保存
     */
    public void addResult(ExperimentResult result) {
        results.add(result);
    }

    /**
     * 全実験結果を取得
     */
    public List<ExperimentResult> getResults() {
        return new ArrayList<>(results);
    }

    /**
     * 実験結果をすべて削除
     */
    public void clearResults() {
        results.clear();
    }

    /**
     * 認証方式ごとの実験結果を取得
     */
    public List<ExperimentResult> getResultsByAuthMethod(
            String authMethod) {

        List<ExperimentResult> filteredResults =
                new ArrayList<>();

        for (ExperimentResult result : results) {

            if (authMethod.equals(
                    result.getAuthMethod())) {

                filteredResults.add(result);
            }
        }

        return filteredResults;
    }

    /**
     * 認証方式ごとの総実験回数
     */
    public int getExperimentCountByAuthMethod(
            String authMethod) {

        return getResultsByAuthMethod(authMethod).size();
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
     * 認証方式ごとの成功時の攻撃時間合計
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
     * 認証方式ごとの平均攻撃成功時間
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

    /*
     * ----------------------------------------
     * 以下は全体集計
     * ----------------------------------------
     */

    /**
     * 全体の総実験回数
     */
    public int getTotalExperimentCount() {
        return results.size();
    }

    /**
     * 全体の成功回数
     */
    public int getSuccessCount() {

        int successCount = 0;

        for (ExperimentResult result : results) {

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

        int successCount =
                getSuccessCount();

        return (double) successCount
                / totalExperimentCount
                * 100.0;
    }

    /**
     * 全体の成功時の攻撃時間合計
     */
    public long getSuccessAttackTimeTotal() {

        long totalTime = 0;

        for (ExperimentResult result : results) {

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

    /**
     * 結果件数
     */
    public int getResultCount() {
        return results.size();
    }
}