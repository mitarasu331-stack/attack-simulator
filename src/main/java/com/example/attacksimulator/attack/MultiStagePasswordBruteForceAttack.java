package com.example.attacksimulator.attack;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class MultiStagePasswordBruteForceAttack {

	private static final int PASSWORD_MIN = 0;
	private static final int PASSWORD_MAX = 9999;
	private static final int PASSWORD_MAX_ATTEMPTS = 10000;

	/**
	 * 試行制限のしきい値
	 *
	 * 1000回失敗するごとに
	 * 試行制限が発生する。
	 */
	private static final int WAIT_INTERVAL =
			1_000;

	/**
	 * 試行制限による仮想待機時間
	 *
	 * 実際には待機しない。
	 *
	 * 1回目：60秒
	 * 2回目：5分
	 * 3回目：10分
	 * 4回目：20分
	 *
	 * 5回目：攻撃処理を強制終了
	 *
	 * ※5回目の強制終了時には
	 * 追加の仮想待機時間は加算しない。
	 */
	private static final long[] WAIT_TIMES = {
			60_000L,       // 1回目：1分
			300_000L,      // 2回目：5分
			600_000L,      // 3回目：10分
			1_200_000L     // 4回目：20分
	};

	/**
	 * 5回目の試行制限で
	 * 攻撃処理を強制終了する。
	 *
	 * 5000回失敗した時点で強制終了。
	 *
	 * 実際のアカウントロックは行わない。
	 */
	private static final int FORCE_TERMINATION_RESTRICTION_COUNT =
			5;

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
				1,
				stageResult.getVirtualWaitTimeMillis(),
				stageResult.isForceTerminated());
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

		// =====================================================
		// Password
		// =====================================================

		BruteForceStageResult passwordResult =
				bruteForce(
						passwordHash,
						maxPassword,
						"Password");

		int totalAttempts =
				passwordResult.getAttemptCount();

		long totalVirtualWaitTimeMillis =
				passwordResult.getVirtualWaitTimeMillis();

		// Password段階で強制終了
		if (passwordResult.isForceTerminated()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					2,
					totalVirtualWaitTimeMillis,
					true);
		}

		// Password突破失敗
		if (!passwordResult.isSuccess()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					2,
					totalVirtualWaitTimeMillis,
					false);
		}

		// =====================================================
		// Password2
		// =====================================================

		BruteForceStageResult password2Result =
				bruteForce(
						password2Hash,
						maxPassword2,
						"Password2");

		totalAttempts +=
				password2Result.getAttemptCount();

		totalVirtualWaitTimeMillis +=
				password2Result.getVirtualWaitTimeMillis();

		// Password2段階で強制終了
		if (password2Result.isForceTerminated()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					null,
					null,
					totalAttempts,
					2,
					totalVirtualWaitTimeMillis,
					true);
		}

		return new AttackResult(
				password2Result.isSuccess(),
				passwordResult.getPassword(),
				password2Result.getPassword(),
				null,
				totalAttempts,
				2,
				totalVirtualWaitTimeMillis,
				false);
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

		// =====================================================
		// Password
		// =====================================================

		BruteForceStageResult passwordResult =
				bruteForce(
						passwordHash,
						maxPassword,
						"Password");

		int totalAttempts =
				passwordResult.getAttemptCount();

		long totalVirtualWaitTimeMillis =
				passwordResult.getVirtualWaitTimeMillis();

		// Password段階で強制終了
		if (passwordResult.isForceTerminated()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					3,
					totalVirtualWaitTimeMillis,
					true);
		}

		// Password突破失敗
		if (!passwordResult.isSuccess()) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					totalAttempts,
					3,
					totalVirtualWaitTimeMillis,
					false);
		}

		// =====================================================
		// Password2
		// =====================================================

		BruteForceStageResult password2Result =
				bruteForce(
						password2Hash,
						maxPassword2,
						"Password2");

		totalAttempts +=
				password2Result.getAttemptCount();

		totalVirtualWaitTimeMillis +=
				password2Result.getVirtualWaitTimeMillis();

		// Password2段階で強制終了
		if (password2Result.isForceTerminated()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					null,
					null,
					totalAttempts,
					3,
					totalVirtualWaitTimeMillis,
					true);
		}

		// Password2突破失敗
		if (!password2Result.isSuccess()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					null,
					null,
					totalAttempts,
					3,
					totalVirtualWaitTimeMillis,
					false);
		}

		// =====================================================
		// Password3
		// =====================================================

		BruteForceStageResult password3Result =
				bruteForce(
						password3Hash,
						maxPassword3,
						"Password3");

		totalAttempts +=
				password3Result.getAttemptCount();

		totalVirtualWaitTimeMillis +=
				password3Result.getVirtualWaitTimeMillis();

		// Password3段階で強制終了
		if (password3Result.isForceTerminated()) {

			return new AttackResult(
					false,
					passwordResult.getPassword(),
					password2Result.getPassword(),
					null,
					totalAttempts,
					3,
					totalVirtualWaitTimeMillis,
					true);
		}

		return new AttackResult(
				password3Result.isSuccess(),
				passwordResult.getPassword(),
				password2Result.getPassword(),
				password3Result.getPassword(),
				totalAttempts,
				3,
				totalVirtualWaitTimeMillis,
				false);
	}

	// =========================================================
	// 共通総当たり処理
	// =========================================================

	private BruteForceStageResult bruteForce(
			String passwordHash,
			int maxAttempts,
			String stageName) {

		int attemptCount = 0;

		long virtualWaitTimeMillis = 0L;

		for (int i = PASSWORD_MIN;
				i <= PASSWORD_MAX
						&& attemptCount < maxAttempts;
				i++) {

			String candidate =
					formatPassword(i);

			attemptCount++;

			// -------------------------------------------------
			// 候補パスワードを1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					stageName
					+ " 総当たり攻撃 試行 "
					+ attemptCount
					+ " / "
					+ maxAttempts
					+ " : "
					+ candidate);

			// -------------------------------------------------
			// BCrypt照合
			// -------------------------------------------------

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				// 成功した場合は、
				// その試行回数が1000回目、
				// 2000回目、3000回目、4000回目、
				// 5000回目であっても
				// 仮想待機時間は加算しない。

				return new BruteForceStageResult(
						true,
						candidate,
						attemptCount,
						virtualWaitTimeMillis,
						false);
			}

			// =================================================
			// 1000回失敗するごとに試行制限
			// =================================================

			if (attemptCount
					% WAIT_INTERVAL == 0) {

				int restrictionCount =
						attemptCount
						/ WAIT_INTERVAL;

				// =================================================
				// 5回目
				// 攻撃処理を強制終了
				//
				// 5000回失敗した時点で終了。
				//
				// 実際のアカウントロックは行わない。
				// =================================================

				if (restrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					System.out.println(
							"========================================");

					System.out.println(
							stageName
							+ " が"
							+ attemptCount
							+ "回失敗");

					System.out.println(
							"試行制限 "
									+ restrictionCount
									+ "回目");

					System.out.println(
							"攻撃処理を強制終了します。");

					System.out.println(
							"※実際のアカウントロックは行いません。");

					System.out.println(
							"累積仮想待機時間 = "
									+ virtualWaitTimeMillis
									+ " ms");

					System.out.println(
							"========================================");

					return new BruteForceStageResult(
							false,
							null,
							attemptCount,
							virtualWaitTimeMillis,
							true);
				}

				// =================================================
				// 1～4回目の試行制限
				// =================================================

				long waitTimeMillis =
						WAIT_TIMES[
						           restrictionCount - 1];

				virtualWaitTimeMillis +=
						waitTimeMillis;

				System.out.println(
						"----------------------------------------");

				System.out.println(
						stageName
						+ " が"
						+ attemptCount
						+ "回失敗");

				System.out.println(
						"試行制限 "
								+ restrictionCount
								+ "回目");

				System.out.println(
						"仮想待機時間 "
								+ waitTimeMillis
								+ " ms を加算");

				System.out.println(
						"累積仮想待機時間 = "
								+ virtualWaitTimeMillis
								+ " ms");

				System.out.println(
						"※実際には待機していません。");

				System.out.println(
						"----------------------------------------");
			}
		}

		return new BruteForceStageResult(
				false,
				null,
				attemptCount,
				virtualWaitTimeMillis,
				false);
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

		private final long virtualWaitTimeMillis;

		/**
		 * 試行制限によって
		 * 攻撃処理が強制終了されたかどうか
		 */
		private final boolean forceTerminated;

		public BruteForceStageResult(
				boolean success,
				String password,
				int attemptCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated) {

			this.success = success;
			this.password = password;
			this.attemptCount = attemptCount;
			this.virtualWaitTimeMillis =
					virtualWaitTimeMillis;
			this.forceTerminated =
					forceTerminated;
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

		public long getVirtualWaitTimeMillis() {
			return virtualWaitTimeMillis;
		}

		public boolean isForceTerminated() {
			return forceTerminated;
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

		private final long virtualWaitTimeMillis;

		/**
		 * 試行制限によって
		 * 攻撃処理が強制終了されたかどうか
		 *
		 * 実際のアカウントロックではない。
		 */
		private final boolean forceTerminated;

		public AttackResult(
				boolean success,
				String password,
				String password2,
				String password3,
				int totalAttempts,
				int stageCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated) {

			this.success = success;
			this.password = password;
			this.password2 = password2;
			this.password3 = password3;
			this.totalAttempts = totalAttempts;
			this.stageCount = stageCount;
			this.virtualWaitTimeMillis =
					virtualWaitTimeMillis;
			this.forceTerminated =
					forceTerminated;
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

		public long getVirtualWaitTimeMillis() {
			return virtualWaitTimeMillis;
		}

		/**
		 * 試行制限によって
		 * 攻撃処理が強制終了されたかどうか
		 *
		 * 実際のアカウントロックではない。
		 */
		public boolean isForceTerminated() {
			return forceTerminated;
		}
	}
}