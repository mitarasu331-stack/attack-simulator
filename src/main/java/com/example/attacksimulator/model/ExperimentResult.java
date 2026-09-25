package com.example.attacksimulator.model;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "experiment_results")
public class ExperimentResult {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	/**
	 * 対象ユーザー名
	 */
	private String username;

	/**
	 * 認証方式
	 */
	private String authMethod;

	/**
	 * 認証構成
	 */
	private String authenticationConfiguration;

	/**
	 * 各段階の最大攻撃試行回数
	 *
	 * 例：
	 * 一段階認証
	 * 10000
	 *
	 * 二段階認証
	 * 10000 → 10000
	 *
	 * 三段階認証
	 * 10000 → 10000 → 10000
	 */
	private String maxAttemptCount;

	/**
	 * 実際の攻撃試行回数
	 */
	private int attemptCount;

	/**
	 * 攻撃成功・失敗
	 */
	private boolean success;

	/**
	 * 突破した認証情報
	 *
	 * 例：
	 * Password=1111
	 *
	 * Password=1111 → Password2=2222
	 *
	 * Password=1111 → Password2=2222 → Password3=3333
	 */
	private String credential;

	/**
	 * 攻撃時間（ms）
	 */
	private long attackTimeMs;

	/**
	 * 実験日時
	 */
	private LocalDateTime experimentDateTime;

	public ExperimentResult() {
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getAuthMethod() {
		return authMethod;
	}

	public void setAuthMethod(String authMethod) {
		this.authMethod = authMethod;
	}

	public String getAuthenticationConfiguration() {
		return authenticationConfiguration;
	}

	public void setAuthenticationConfiguration(
			String authenticationConfiguration) {

		this.authenticationConfiguration =
				authenticationConfiguration;
	}

	public String getMaxAttemptCount() {
		return maxAttemptCount;
	}

	public void setMaxAttemptCount(
			String maxAttemptCount) {

		this.maxAttemptCount = maxAttemptCount;
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