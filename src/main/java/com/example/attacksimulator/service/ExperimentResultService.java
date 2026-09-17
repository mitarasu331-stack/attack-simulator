package com.example.attacksimulator.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.model.ExperimentResult;

@Service
public class ExperimentResultService {

    private final List<ExperimentResult> results =
            new ArrayList<>();

    public void addResult(ExperimentResult result) {
        results.add(result);
    }

    public List<ExperimentResult> getResults() {
        return new ArrayList<>(results);
    }

    public void clearResults() {
        results.clear();
    }

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

    public int getExperimentCountByAuthMethod(
            String authMethod) {

        return getResultsByAuthMethod(authMethod).size();
    }

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

        List<ExperimentResult> filteredResults =
                getResultsByAuthMethod(authMethod);

        if (filteredResults.isEmpty()) {
            return 0.0;
        }

        long totalAttemptCount = 0;

        for (ExperimentResult result :
                filteredResults) {

            totalAttemptCount +=
                    result.getAttemptCount();
        }

        return (double) totalAttemptCount
                / filteredResults.size();
    }

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

    // ----------------------------------------
    // 全体集計
    // ----------------------------------------

    public int getTotalExperimentCount() {
        return results.size();
    }

    public int getSuccessCount() {

        int successCount = 0;

        for (ExperimentResult result : results) {

            if (result.isSuccess()) {
                successCount++;
            }
        }

        return successCount;
    }

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
     * 全認証方式の平均攻撃試行回数
     */
    public double getAverageAttemptCount() {

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

    public int getResultCount() {
        return results.size();
    }
}