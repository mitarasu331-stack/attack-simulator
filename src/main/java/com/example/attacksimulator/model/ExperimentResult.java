package com.example.attacksimulator.model;

import java.time.LocalDateTime;

public class ExperimentResult {

    private String authMethod;

    private int operationCount;

    private int attemptCount;

    private boolean success;

    private String credential;

    private long attackTimeMs;

    private LocalDateTime experimentDateTime;

    public ExperimentResult() {
    }

    public ExperimentResult(
            String authMethod,
            int operationCount,
            int attemptCount,
            boolean success,
            String credential,
            long attackTimeMs,
            LocalDateTime experimentDateTime) {

        this.authMethod = authMethod;
        this.operationCount = operationCount;
        this.attemptCount = attemptCount;
        this.success = success;
        this.credential = credential;
        this.attackTimeMs = attackTimeMs;
        this.experimentDateTime = experimentDateTime;
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