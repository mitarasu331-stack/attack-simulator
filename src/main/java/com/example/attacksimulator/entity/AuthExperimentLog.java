package com.example.attacksimulator.entity;

import java.math.BigDecimal;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "auth_experiment_logs")
public class AuthExperimentLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 実験ID
    @Column(name = "experiment_id", nullable = false, length = 50)
    private String experimentId;

    // 何回目の試行か
    @Column(name = "attempt_number", nullable = false)
    private Integer attemptNumber;

    // 認証方式
    @Column(name = "auth_method", nullable = false, length = 100)
    private String authMethod;

    // 認証タイプ
    @Column(name = "auth_type", nullable = false, length = 100)
    private String authType;

    // 攻撃方法
    @Column(name = "attack_type", nullable = false, length = 100)
    private String attackType;

    // 試した値
    @Column(name = "candidate", nullable = false, length = 100)
    private String candidate;

    // 成功したか
    @Column(name = "success", nullable = false)
    private Boolean success;

    // 1回の試行にかかった時間
    @Column(name = "duration_ms", nullable = false, precision = 10, scale = 2)
    private BigDecimal durationMs;

    // 試行日時
    @Column(name = "execution_time", nullable = false)
    private LocalDateTime executionTime;


    public Long getId() {
        return id;
    }

    public String getExperimentId() {
        return experimentId;
    }

    public void setExperimentId(String experimentId) {
        this.experimentId = experimentId;
    }

    public Integer getAttemptNumber() {
        return attemptNumber;
    }

    public void setAttemptNumber(Integer attemptNumber) {
        this.attemptNumber = attemptNumber;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    public String getCandidate() {
        return candidate;
    }

    public void setCandidate(String candidate) {
        this.candidate = candidate;
    }

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public BigDecimal getDurationMs() {
        return durationMs;
    }

    public void setDurationMs(BigDecimal durationMs) {
        this.durationMs = durationMs;
    }

    public LocalDateTime getExecutionTime() {
        return executionTime;
    }

    public void setExecutionTime(LocalDateTime executionTime) {
        this.executionTime = executionTime;
    }
}