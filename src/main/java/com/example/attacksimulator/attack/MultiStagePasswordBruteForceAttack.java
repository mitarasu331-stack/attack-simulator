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

	public AttackResult executeOneStage(
			String passwordHash) {

		return executeOneStage(
				passwordHash,
				PASSWORD_MAX_ATTEMPTS);
	}

	public AttackResult executeOneStage(
			String passwordHash,
			int maxAttemptsPassword) {

		validateHash(passwordHash);

		int maxAttempts =
				clampAttempts(maxAttemptsPassword);

		BruteForceStageResult stageResult =
				bruteForce(
						passwordHash,
						maxAttempts,
						"Password");

		return new AttackResult(
				stageResult.isSuccess(),
				stageResult.getPassword(),
				null,
				null,
				stageResult.getAttemptCount(),
				1);
	}

	// =========================================================
	// 二段階認証
	// Password → Password2
	// =========================================================

	public AttackResult executeTwoStage(
			String passwordHash,
			String password2Hash) {

		return executeTwoStage(
				passwordHash,
				password2Hash,
				PASSWORD_MAX_ATTEMPTS,
				PASSWORD_MAX_ATTEMPTS);
	}

	public AttackResult executeTwoStage(
			String passwordHash,
			String password2Hash,
			int maxAttemptsPassword,
			int maxAttemptsPassword2) {

		validateHash(passwordHash);
		validateHash(password2Hash);

		int maxPassword =
				clampAttempts(maxAttemptsPassword);

		int maxPassword2 =
				clampAttempts(maxAttemptsPassword2);

		BruteForceStageResult passwordResult =
				bruteForce(
						passwordHash,
						maxPassword,
						"Password");

		int totalAttempts =
				passwordResult.getAttemptCount();

		if (!passwordResult.isSuccess()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					2);
		}

		BruteForceStageResult password2Result =
				bruteForce(
						password2Hash,
						maxPassword2,
						"Password2");

		totalAttempts +=
				password2Result.getAttemptCount();

		return new AttackResult(
				password2Result.isSuccess(),
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

		int maxPassword =
				clampAttempts(maxAttemptsPassword);

		int maxPassword2 =
				clampAttempts(maxAttemptsPassword2);

		int maxPassword3 =
				clampAttempts(maxAttemptsPassword3);

		BruteForceStageResult passwordResult =
				bruteForce(
						passwordHash,
						maxPassword,
						"Password");

		int totalAttempts =
				passwordResult.getAttemptCount();

		if (!passwordResult.isSuccess()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					3);
		}

		BruteForceStageResult password2Result =
				bruteForce(
						password2Hash,
						maxPassword2,
						"Password2");

		totalAttempts +=
				password2Result.getAttemptCount();

		if (!password2Result.isSuccess()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					null,
					null,
					totalAttempts,
					3);
		}

		BruteForceStageResult password3Result =
				bruteForce(
						password3Hash,
						maxPassword3,
						"Password3");

		totalAttempts +=
				password3Result.getAttemptCount();

		return new AttackResult(
				password3Result.isSuccess(),
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
			int maxAttempts,
			String stageName) {

		int attemptCount = 0;

		for (int i = PASSWORD_MIN;
				i <= PASSWORD_MAX
						&& attemptCount < maxAttempts;
				i++) {

			String candidate =
					formatPassword(i);

			attemptCount++;

			// 候補パスワードを1件ずつ表示
			System.out.println(
					stageName
							+ " 総当たり攻撃 試行 "
							+ attemptCount
							+ " / "
							+ maxAttempts
							+ " : "
							+ candidate);

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

	private String formatPassword(
			int value) {

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