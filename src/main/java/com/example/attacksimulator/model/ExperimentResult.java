package com.example.attacksimulator.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "experiment_results")
public class ExperimentResult {

    /**
     * DB内部で使用するID
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 実験番号
     */
    @Column(name = "experiment_number", nullable = false)
    private int experimentNumber;

    /**
     * 認証方式
     */
    @Column(name = "auth_method", nullable = false)
    private String authMethod;

    /**
     * 認証操作回数
     */
    @Column(name = "operation_count")
    private int operationCount;

    /**
     * 認証構成
     */
    @Column(name = "authentication_configuration")
    private String authenticationConfiguration;

    /**
     * 攻撃で設定された最大試行回数
     */
    @Column(name = "max_attempt_count")
    private int maxAttemptCount;

    /**
     * 実際に攻撃を行った試行回数
     */
    @Column(name = "attempt_count")
    private int attemptCount;

    /**
     * 攻撃成功・失敗
     */
    @Column(name = "success")
    private boolean success;

    /**
     * 突破した認証情報
     */
    @Column(name = "credential")
    private String credential;

    /**
     * 攻撃時間
     */
    @Column(name = "attack_time_ms")
    private long attackTimeMs;

    /**
     * 実験日時
     */
    @Column(name = "experiment_date_time")
    private LocalDateTime experimentDateTime;

    /**
     * デフォルトコンストラクタ
     */
    public ExperimentResult() {
    }

    /**
     * コンストラクタ
     */
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

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public void setOperationCount(
            int operationCount) {

        this.operationCount =
                operationCount;
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