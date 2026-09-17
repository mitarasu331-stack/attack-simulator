package com.example.attacksimulator.model;

import java.time.LocalDateTime;

public class ExperimentResult {

    /**
     * 実験番号
     */
    private int experimentNumber;

    /**
     * 認証方式
     */
    private String authMethod;

    /**
     * 認証操作回数
     */
    private int operationCount;

    /**
     * 認証構成
     */
    private String authenticationConfiguration;

    /**
     * 攻撃で設定された最大試行回数
     */
    private int maxAttemptCount;

    /**
     * 実際に攻撃を行った試行回数
     */
    private int attemptCount;

    /**
     * 攻撃成功・失敗
     */
    private boolean success;

    /**
     * 突破した認証情報
     */
    private String credential;

    /**
     * 攻撃時間
     */
    private long attackTimeMs;

    /**
     * 実験日時
     */
    private LocalDateTime experimentDateTime;

    public ExperimentResult() {
    }

    public ExperimentResult(
            int experimentNumber,
            String authMethod,
            int operationCount,
            String authenticationConfiguration,
            int maxAttemptCount,
            int attemptCount,
            boolean success,
            String credential,
            long attackTimeMs,
            LocalDateTime experimentDateTime) {

        this.experimentNumber = experimentNumber;
        this.authMethod = authMethod;
        this.operationCount = operationCount;
        this.authenticationConfiguration =
                authenticationConfiguration;
        this.maxAttemptCount = maxAttemptCount;
        this.attemptCount = attemptCount;
        this.success = success;
        this.credential = credential;
        this.attackTimeMs = attackTimeMs;
        this.experimentDateTime =
                experimentDateTime;
    }

    public int getExperimentNumber() {
        return experimentNumber;
    }

    public void setExperimentNumber(
            int experimentNumber) {

        this.experimentNumber =
                experimentNumber;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public int getOperationCount() {
        return operationCount;
    }

    public void setOperationCount(int operationCount) {
        this.operationCount = operationCount;
    }

    public String getAuthenticationConfiguration() {
        return authenticationConfiguration;
    }

    public void setAuthenticationConfiguration(
            String authenticationConfiguration) {

        this.authenticationConfiguration =
                authenticationConfiguration;
    }

    public int getMaxAttemptCount() {
        return maxAttemptCount;
    }

    public void setMaxAttemptCount(
            int maxAttemptCount) {

        this.maxAttemptCount =
                maxAttemptCount;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public void setAttemptCount(int attemptCount) {
        this.attemptCount = attemptCount;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    public long getAttackTimeMs() {
        return attackTimeMs;
    }

    public void setAttackTimeMs(long attackTimeMs) {
        this.attackTimeMs = attackTimeMs;
    }

    public LocalDateTime getExperimentDateTime() {
        return experimentDateTime;
    }

    public void setExperimentDateTime(
            LocalDateTime experimentDateTime) {

        this.experimentDateTime =
                experimentDateTime;
    }
}