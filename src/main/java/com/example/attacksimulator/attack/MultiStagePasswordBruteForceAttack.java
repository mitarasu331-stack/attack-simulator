package com.example.attacksimulator.attack;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class MultiStagePasswordBruteForceAttack {

	private static final int PASSWORD_MIN = 0;
	private static final int PASSWORD_MAX = 9999;
	private static final int PASSWORD_MAX_ATTEMPTS = 10000;

	private final PasswordEncoder passwordEncoder;

	public MultiStagePasswordBruteForceAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder = passwordEncoder;
	}

	// =========================================================
	// 一段階認証
	// =========================================================

	/**
	 * 既存互換版
	 *
	 * Password最大10000回
	 */
	public AttackResult executeOneStage(
			String passwordHash) {

		return executeOneStage(
				passwordHash,
				PASSWORD_MAX_ATTEMPTS);
	}

	/**
	 * Passwordの最大試行回数を指定
	 */
	public AttackResult executeOneStage(
			String passwordHash,
			int maxAttemptsPassword) {

		validateHash(passwordHash);

		int actualMaxAttempts =
				clampAttempts(
						maxAttemptsPassword);

		int attemptCount = 0;

		for (int i = PASSWORD_MIN;
				i <= PASSWORD_MAX;
				i++) {

			if (attemptCount >= actualMaxAttempts) {
				break;
			}

			String candidate =
					formatPassword(i);

			attemptCount++;

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				return new AttackResult(
						true,
						candidate,
						null,
						null,
						attemptCount,
						1);
			}
		}

		return new AttackResult(
				false,
				null,
				null,
				null,
				attemptCount,
				1);
	}

	// =========================================================
	// 二段階認証
	// Password → Password2
	// =========================================================

	/**
	 * 既存互換版
	 *
	 * Password 10000回
	 * Password2 10000回
	 */
	public AttackResult executeTwoStage(
			String passwordHash,
			String password2Hash) {

		return executeTwoStage(
				passwordHash,
				password2Hash,
				PASSWORD_MAX_ATTEMPTS,
				PASSWORD_MAX_ATTEMPTS);
	}

	/**
	 * Password / Password2 の最大試行回数を個別指定
	 */
	public AttackResult executeTwoStage(
			String passwordHash,
			String password2Hash,
			int maxAttemptsPassword,
			int maxAttemptsPassword2) {

		validateHash(passwordHash);
		validateHash(password2Hash);

		int actualMaxAttemptsPassword =
				clampAttempts(
						maxAttemptsPassword);

		int actualMaxAttemptsPassword2 =
				clampAttempts(
						maxAttemptsPassword2);

		// =====================================================
		// Password
		// =====================================================

		BruteForceStageResult passwordResult =
				bruteForce(
						passwordHash,
						actualMaxAttemptsPassword);

		int totalAttempts =
				passwordResult.getAttemptCount();

		// Passwordで失敗した場合
		if (!passwordResult.isSuccess()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					2);
		}

		// =====================================================
		// Password2
		// =====================================================

		BruteForceStageResult password2Result =
				bruteForce(
						password2Hash,
						actualMaxAttemptsPassword2);

		totalAttempts +=
				password2Result.getAttemptCount();

		// Password2で失敗した場合
		if (!password2Result.isSuccess()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					null,
					null,
					totalAttempts,
					2);
		}

		// =====================================================
		// 全段階成功
		// =====================================================

		return new AttackResult(
				true,
				passwordResult.getPassword(),
				password2Result.getPassword(),
				null,
				totalAttempts,
				2);
	}

	// =========================================================
	// 三段階認証
	// Password → Password2 → Password3
	// =========================================================

	/**
	 * 既存互換版
	 *
	 * すべて最大10000回
	 */
	public AttackResult executeThreeStage(
			String passwordHash,
			String password2Hash,
			String password3Hash) {

		return executeThreeStage(
				passwordHash,
				password2Hash,
				password3Hash,
				PASSWORD_MAX_ATTEMPTS,
				PASSWORD_MAX_ATTEMPTS,
				PASSWORD_MAX_ATTEMPTS);
	}

	/**
	 * Password / Password2 / Password3 を個別指定
	 */
	public AttackResult executeThreeStage(
			String passwordHash,
			String password2Hash,
			String password3Hash,
			int maxAttemptsPassword,
			int maxAttemptsPassword2,
			int maxAttemptsPassword3) {

		validateHash(passwordHash);
		validateHash(password2Hash);
		validateHash(password3Hash);

		int actualMaxAttemptsPassword =
				clampAttempts(
						maxAttemptsPassword);

		int actualMaxAttemptsPassword2 =
				clampAttempts(
						maxAttemptsPassword2);

		int actualMaxAttemptsPassword3 =
				clampAttempts(
						maxAttemptsPassword3);

		int totalAttempts = 0;

		// =====================================================
		// Password
		// =====================================================

		BruteForceStageResult passwordResult =
				bruteForce(
						passwordHash,
						actualMaxAttemptsPassword);

		totalAttempts +=
				passwordResult.getAttemptCount();

		// Passwordで失敗
		if (!passwordResult.isSuccess()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					3);
		}

		// =====================================================
		// Password2
		// =====================================================

		BruteForceStageResult password2Result =
				bruteForce(
						password2Hash,
						actualMaxAttemptsPassword2);

		totalAttempts +=
				password2Result.getAttemptCount();

		// Password2で失敗
		if (!password2Result.isSuccess()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					null,
					null,
					totalAttempts,
					3);
		}

		// =====================================================
		// Password3
		// =====================================================

		BruteForceStageResult password3Result =
				bruteForce(
						password3Hash,
						actualMaxAttemptsPassword3);

		totalAttempts +=
				password3Result.getAttemptCount();

		// Password3で失敗
		if (!password3Result.isSuccess()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					password2Result.getPassword(),
					null,
					totalAttempts,
					3);
		}

		// =====================================================
		// 全段階成功
		// =====================================================

		return new AttackResult(
				true,
				passwordResult.getPassword(),
				password2Result.getPassword(),
				password3Result.getPassword(),
				totalAttempts,
				3);
	}

	// =========================================================
	// 共通総当たり処理
	// =========================================================

	private BruteForceStageResult bruteForce(
			String passwordHash,
			int maxAttempts) {

		int attemptCount = 0;

		for (int i = PASSWORD_MIN;
				i <= PASSWORD_MAX;
				i++) {

			if (attemptCount >= maxAttempts) {
				break;
			}

			String candidate =
					formatPassword(i);

			attemptCount++;

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				return new BruteForceStageResult(
						true,
						candidate,
						attemptCount);
			}
		}

		return new BruteForceStageResult(
				false,
				null,
				attemptCount);
	}

	// =========================================================
	// 試行回数の制限
	// =========================================================

	private int clampAttempts(
			int maxAttempts) {

		if (maxAttempts < 1) {
			return 1;
		}

		if (maxAttempts > PASSWORD_MAX_ATTEMPTS) {
			return PASSWORD_MAX_ATTEMPTS;
		}

		return maxAttempts;
	}

	// =========================================================
	// Password形式
	// =========================================================

	private String formatPassword(int value) {

		return String.format(
				"%04d",
				value);
	}

	// =========================================================
	// ハッシュチェック
	// =========================================================

	private void validateHash(
			String passwordHash) {

		if (passwordHash == null
				|| passwordHash.isBlank()) {

			throw new IllegalArgumentException(
					"パスワードハッシュが指定されていません。");
		}
	}

	// =========================================================
	// 1段階の総当たり結果
	// =========================================================

	private static class BruteForceStageResult {

		private final boolean success;

		private final String password;

		private final int attemptCount;

		public BruteForceStageResult(
				boolean success,
				String password,
				int attemptCount) {

			this.success = success;

			this.password = password;

			this.attemptCount = attemptCount;
		}

		public boolean isSuccess() {
			return success;
		}

		public String getPassword() {
			return password;
		}

		public int getAttemptCount() {
			return attemptCount;
		}
	}

	// =========================================================
	// 多段階認証の総当たり結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String password;

		private final String password2;

		private final String password3;

		private final int totalAttempts;

		private final int stageCount;

		public AttackResult(
				boolean success,
				String password,
				String password2,
				String password3,
				int totalAttempts,
				int stageCount) {

			this.success = success;

			this.password = password;

			this.password2 = password2;

			this.password3 = password3;

			this.totalAttempts = totalAttempts;

			this.stageCount = stageCount;
		}

		public boolean isSuccess() {
			return success;
		}

		public String getPassword() {
			return password;
		}

		public String getPassword2() {
			return password2;
		}

		public String getPassword3() {
			return password3;
		}

		public int getTotalAttempts() {
			return totalAttempts;
		}

		public int getStageCount() {
			return stageCount;
		}
	}
}