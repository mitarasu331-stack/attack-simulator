package com.example.attacksimulator.attack;

import java.util.List;

import org.springframework.stereotype.Component;

@Component
public class DictionaryPasswordAttack {

	/**
	 * 仮想待機時間を加算する間隔
	 *
	 * 10回失敗ごとに制限を適用する。
	 */
	private static final int WAIT_INTERVAL =
			10;

	/**
	 * 10回失敗するごとの仮想待機時間
	 *
	 * 実際には待機しない。
	 * 攻撃時間に仮想的に加算する。
	 *
	 * 1回目：1分
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
	 * 5回目の制限
	 *
	 * 辞書攻撃では10回ごとに制限するため、
	 * 50回失敗した時点で攻撃処理を強制終了する。
	 *
	 * 実際のアカウントロックは行わない。
	 */
	private static final int FORCE_TERMINATION_RESTRICTION_COUNT =
			5;

	// =========================================================
	// 一段階認証
	// =========================================================

	public AttackResult executeOneStage(
			int maxEntries,
			PasswordVerifier verifier) {

		List<String> dictionary =
				DictionaryPasswordList.getPasswords(maxEntries);

		int attemptCount = 0;

		long virtualWaitTimeMillis = 0L;

		boolean forceTerminated = false;

		for (String password : dictionary) {

			attemptCount++;

			System.out.println(
					"辞書攻撃 試行 "
							+ attemptCount
							+ " / "
							+ dictionary.size()
							+ " : "
							+ password);

			boolean success =
					verifier.verify(password);

			// =================================================
			// 認証成功
			// =================================================

			if (success) {

				/*
				 * 成功した場合は制限処理を行わない。
				 *
				 * 例えば50回目で成功した場合でも、
				 * 50回目の制限による仮想待機時間は
				 * 加算しない。
				 */
				return new AttackResult(
						1,
						true,
						password,
						null,
						null,
						attemptCount,
						attemptCount,
						0,
						0,
						virtualWaitTimeMillis,
						false);
			}

			// =================================================
			// 10回失敗するごとに制限
			// =================================================

			if (attemptCount % WAIT_INTERVAL == 0) {

				int restrictionCount =
						attemptCount / WAIT_INTERVAL;

				System.out.println(
						"----------------------------------------");

				System.out.println(
						"辞書攻撃が"
								+ attemptCount
								+ "回失敗しました。");

				System.out.println(
						"今回の制限回数 = "
								+ restrictionCount
								+ "回目");

				// =================================================
				// 5回目 → 攻撃処理を強制終了
				// =================================================

				if (restrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					forceTerminated = true;

					System.out.println(
							"辞書攻撃が"
									+ attemptCount
									+ "回失敗しました。");

					System.out.println(
							"5回目の制限に到達したため、"
									+ "攻撃処理を強制終了します。");

					System.out.println(
							"実際のアカウントロックは行いません。");

					System.out.println(
							"疑似的なロックとして"
									+ "攻撃処理のみ終了します。");

					System.out.println(
							"累積仮想待機時間 = "
									+ virtualWaitTimeMillis
									+ " ms");

					System.out.println(
							"----------------------------------------");

					return new AttackResult(
							1,
							false,
							null,
							null,
							null,
							attemptCount,
							attemptCount,
							0,
							0,
							virtualWaitTimeMillis,
							forceTerminated);
				}

				// =================================================
				// 1～4回目 → 仮想待機時間を加算
				// =================================================

				long waitTimeMillis =
						WAIT_TIMES[
								restrictionCount - 1];

				virtualWaitTimeMillis +=
						waitTimeMillis;

				System.out.println(
						"辞書攻撃が"
								+ attemptCount
								+ "回失敗したため"
								+ "仮想待機時間を加算します。");

				System.out.println(
						"現在の試行回数 = "
								+ attemptCount);

				System.out.println(
						"今回の仮想待機時間 = "
								+ waitTimeMillis
								+ " ms");

				System.out.println(
						"累積仮想待機時間 = "
								+ virtualWaitTimeMillis
								+ " ms");

				System.out.println(
						"----------------------------------------");
			}
		}

		// =====================================================
		// 全辞書候補失敗
		// =====================================================

		return new AttackResult(
				1,
				false,
				null,
				null,
				null,
				attemptCount,
				attemptCount,
				0,
				0,
				virtualWaitTimeMillis,
				forceTerminated);
	}

	// =========================================================
	// 一段階用
	// =========================================================

	@FunctionalInterface
	public interface PasswordVerifier {

		boolean verify(String password);
	}

	// =========================================================
	// 攻撃結果
	// =========================================================

	public static class AttackResult {

		private final int stageCount;

		private final boolean success;

		private final String password;

		private final String password2;

		private final String password3;

		private final int totalAttempts;

		private final int passwordAttemptCount;

		private final int password2AttemptCount;

		private final int password3AttemptCount;

		private final long virtualWaitTimeMillis;

		/**
		 * 攻撃処理が強制終了されたか
		 *
		 * true：
		 * 50回失敗による疑似的なロック
		 *
		 * false：
		 * 通常終了
		 */
		private final boolean forceTerminated;

		// =====================================================
		// 既存コンストラクタ
		// =====================================================

		public AttackResult(
				int stageCount,
				boolean success,
				String password,
				String password2,
				String password3,
				int totalAttempts,
				int passwordAttemptCount,
				int password2AttemptCount) {

			this(
					stageCount,
					success,
					password,
					password2,
					password3,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					0,
					0L,
					false);
		}

		// =====================================================
		// 既存コンストラクタ
		// =====================================================

		public AttackResult(
				int stageCount,
				boolean success,
				String password,
				String password2,
				String password3,
				int totalAttempts,
				int passwordAttemptCount,
				int password2AttemptCount,
				int password3AttemptCount) {

			this(
					stageCount,
					success,
					password,
					password2,
					password3,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					password3AttemptCount,
					0L,
					false);
		}

		// =====================================================
		// 仮想待機時間対応コンストラクタ
		// =====================================================

		public AttackResult(
				int stageCount,
				boolean success,
				String password,
				String password2,
				String password3,
				int totalAttempts,
				int passwordAttemptCount,
				int password2AttemptCount,
				int password3AttemptCount,
				long virtualWaitTimeMillis) {

			this(
					stageCount,
					success,
					password,
					password2,
					password3,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					password3AttemptCount,
					virtualWaitTimeMillis,
					false);
		}

		// =====================================================
		// 仮想待機時間 + 強制終了対応コンストラクタ
		// =====================================================

		public AttackResult(
				int stageCount,
				boolean success,
				String password,
				String password2,
				String password3,
				int totalAttempts,
				int passwordAttemptCount,
				int password2AttemptCount,
				int password3AttemptCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated) {

			this.stageCount =
					stageCount;

			this.success =
					success;

			this.password =
					password;

			this.password2 =
					password2;

			this.password3 =
					password3;

			this.totalAttempts =
					totalAttempts;

			this.passwordAttemptCount =
					passwordAttemptCount;

			this.password2AttemptCount =
					password2AttemptCount;

			this.password3AttemptCount =
					password3AttemptCount;

			this.virtualWaitTimeMillis =
					virtualWaitTimeMillis;

			this.forceTerminated =
					forceTerminated;
		}

		// =====================================================
		// Getter
		// =====================================================

		public int getStageCount() {

			return stageCount;
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

		public int getPasswordAttemptCount() {

			return passwordAttemptCount;
		}

		public int getPassword2AttemptCount() {

			return password2AttemptCount;
		}

		public int getPassword3AttemptCount() {

			return password3AttemptCount;
		}

		public long getVirtualWaitTimeMillis() {

			return virtualWaitTimeMillis;
		}

		/**
		 * 攻撃処理が強制終了されたか
		 *
		 * @return true = 強制終了
		 */
		public boolean isForceTerminated() {

			return forceTerminated;
		}
	}
}