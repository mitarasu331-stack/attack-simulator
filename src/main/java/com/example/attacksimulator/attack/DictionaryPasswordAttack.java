package com.example.attacksimulator.attack;

import java.util.List;

import org.springframework.stereotype.Component;

@Component
public class DictionaryPasswordAttack {

	/**
	 * 辞書攻撃では10回失敗するごとに
	 * 仮想的に1分の待機時間を加算する。
	 *
	 * 実際には待機しない。
	 *
	 * 60秒 = 60000ms
	 */
	private static final long WAIT_TIME_MILLIS =
			60_000L;

	/**
	 * 仮想待機時間を加算する間隔
	 *
	 * 10回失敗ごとに1分
	 */
	private static final int WAIT_INTERVAL =
			10;

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

				// 10回目などで成功した場合は、
				// 仮想待機時間を追加しない。
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
						virtualWaitTimeMillis);
			}

			// =================================================
			// 10回失敗するごとに仮想待機時間を加算
			// =================================================

			if (attemptCount % WAIT_INTERVAL == 0) {

				virtualWaitTimeMillis +=
						WAIT_TIME_MILLIS;

				System.out.println(
						"----------------------------------------");

				System.out.println(
						"辞書攻撃が"
								+ attemptCount
								+ "回失敗したため"
								+ "仮想待機時間を1分加算します。");

				System.out.println(
						"現在の試行回数 = "
								+ attemptCount);

				System.out.println(
						"今回の仮想待機時間 = "
								+ WAIT_TIME_MILLIS
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
				virtualWaitTimeMillis);
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
					0L);
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
					0L);
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
	}
}