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
@Table(name = "auth_experiments")
public class AuthExperiment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 実験ID
     */
    @Column(name = "experiment_id", nullable = false, length = 50)
    private String experimentId;

    /**
     * 使用する認証要素
     * 例：Password
     * 例：Password+Email OTP
     */
    @Column(name = "auth_method", nullable = false, length = 100)
    private String authMethod;

    /**
     * 段階数または要素数
     * 1～3
     */
    @Column(name = "auth_count", nullable = false)
    private Integer authCount;

    /**
     * 認証方式の種類
     * 例：段階認証
     * 例：要素認証
     */
    @Column(name = "auth_type", nullable = false, length = 100)
    private String authType;

    /**
     * 攻撃方法
     * 例：password-bruteforce-attack
     */
    @Column(name = "attack_type", nullable = false, length = 100)
    private String attackType;

    /**
     * 突破試行回数
     */
    @Column(name = "total_count", nullable = false)
    private Integer totalCount;

    /**
     * 突破成功回数
     */
    @Column(name = "success_count", nullable = false)
    private Integer successCount;

    /**
     * 実行時間合計（ms）
     */
    @Column(name = "total_duration_ms", nullable = false, precision = 10, scale = 2)
    private BigDecimal totalDurationMs;

    /**
     * 実験日時
     */
    @Column(name = "auth_time", nullable = false)
    private LocalDateTime authTime;


    // =========================
    // Getter / Setter
    // =========================

    public Long getId() {
        return id;
    }

    public String getExperimentId() {
        return experimentId;
    }

    public void setExperimentId(String experimentId) {
        this.experimentId = experimentId;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public Integer getAuthCount() {
        return authCount;
    }

    public void setAuthCount(Integer authCount) {
        this.authCount = authCount;
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

    public Integer getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(Integer totalCount) {
        this.totalCount = totalCount;
    }

    public Integer getSuccessCount() {
        return successCount;
    }

    public void setSuccessCount(Integer successCount) {
        this.successCount = successCount;
    }

    public BigDecimal getTotalDurationMs() {
        return totalDurationMs;
    }

    public void setTotalDurationMs(BigDecimal totalDurationMs) {
        this.totalDurationMs = totalDurationMs;
    }

    public LocalDateTime getAuthTime() {
        return authTime;
    }

    public void setAuthTime(LocalDateTime authTime) {
        this.authTime = authTime;
    }
}