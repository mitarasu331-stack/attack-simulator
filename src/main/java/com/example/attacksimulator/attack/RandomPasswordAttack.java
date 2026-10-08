package com.example.attacksimulator.attack;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class RandomPasswordAttack {

	// =========================================================
	// 定数
	// =========================================================

	/**
	 * 4桁Passwordの総組み合わせ数
	 *
	 * 0000 ～ 9999
	 */
	private static final int TOTAL_PASSWORD_COUNT =
			10_000;

	/**
	 * 仮想待機時間
	 *
	 * 実際には待機しない。
	 * 実験上の攻撃時間にだけ加算する。
	 *
	 * 1回目の制限 = 1分
	 *
	 * 60秒 = 60000ms
	 */
	private static final long FIRST_WAIT_TIME_MILLIS =
			60_000L;

	/**
	 * 仮想待機が発生する間隔
	 *
	 * 1000回失敗するごとに制限が発生する。
	 */
	private static final int WAIT_INTERVAL =
			1_000;

	/**
	 * 制限回数ごとの仮想待機時間
	 *
	 * 1回目 = 1分
	 * 2回目 = 5分
	 * 3回目 = 10分
	 * 4回目 = 20分
	 *
	 * 5回目は強制終了するため、
	 * 待機時間は設定しない。
	 */
	private static final long[] WAIT_TIMES = {

			60_000L,       // 1分
			300_000L,      // 5分
			600_000L,      // 10分
			1_200_000L     // 20分
	};

	/**
	 * 強制終了する制限回数
	 *
	 * 1000回 × 5回
	 * = 5000回失敗
	 *
	 * 5回目の制限に到達した時点で
	 * 攻撃処理を強制終了する。
	 *
	 * 実際のアカウントロックは行わない。
	 */
	private static final int FORCE_TERMINATION_RESTRICTION_COUNT =
			5;

	// =========================================================
	// PasswordEncoder
	// =========================================================

	private final PasswordEncoder passwordEncoder;

	/**
	 * 乱数生成器
	 */
	private final SecureRandom secureRandom;

	// =========================================================
	// コンストラクタ
	// =========================================================

	public RandomPasswordAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder =
				passwordEncoder;

		this.secureRandom =
				new SecureRandom();
	}

	// =========================================================
	// ランダム攻撃
	// 既存互換用
	// =========================================================

	public AttackResult execute(
			String passwordHash) {

		return execute(
				passwordHash,
				TOTAL_PASSWORD_COUNT);
	}

	// =========================================================
	// ランダム攻撃
	// 最大試行回数指定
	// =========================================================

	public AttackResult execute(
			String passwordHash,
			int maxAttempts) {

		// =====================================================
		// 入力チェック
		// =====================================================

		if (passwordHash == null
				|| passwordHash.isBlank()) {

			throw new IllegalArgumentException(
					"パスワードハッシュが指定されていません。");
		}

		// =====================================================
		// 最大試行回数を制限
		// =====================================================

		int actualMaxAttempts =
				clampAttempts(
						maxAttempts);

		// =====================================================
		// 0000～9999を作成
		// =====================================================

		List<Integer> candidates =
				new ArrayList<>(
						TOTAL_PASSWORD_COUNT);

		for (int i = 0;
				i < TOTAL_PASSWORD_COUNT;
				i++) {

			candidates.add(i);
		}

		// =====================================================
		// 候補をランダムな順番に並べ替える
		// =====================================================

		Collections.shuffle(
				candidates,
				secureRandom);

		// =====================================================
		// ランダム攻撃
		// =====================================================

		int attemptCount = 0;

		/**
		 * 現在までに発生した制限回数
		 *
		 * 1000回失敗
		 * → 1回目
		 *
		 * 2000回失敗
		 * → 2回目
		 *
		 * 3000回失敗
		 * → 3回目
		 *
		 * 4000回失敗
		 * → 4回目
		 *
		 * 5000回失敗
		 * → 5回目、強制終了
		 */
		int restrictionCount = 0;

		/**
		 * 累積仮想待機時間
		 */
		long virtualWaitTimeMillis = 0L;

		for (int i = 0;
				i < candidates.size();
				i++) {

			// -------------------------------------------------
			// 最大試行回数に到達
			// -------------------------------------------------

			if (attemptCount
					>= actualMaxAttempts) {

				break;
			}

			int candidateNumber =
					candidates.get(i);

			// -------------------------------------------------
			// 4桁に変換
			//
			// 1    → 0001
			// 42   → 0042
			// 1234 → 1234
			// -------------------------------------------------

			String candidate =
					String.format(
							"%04d",
							candidateNumber);

			// -------------------------------------------------
			// 試行回数を増やす
			// -------------------------------------------------

			attemptCount++;

			// -------------------------------------------------
			// 候補を1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					"ランダムPassword 試行 "
							+ attemptCount
							+ " / "
							+ actualMaxAttempts
							+ " : "
							+ candidate);

			// -------------------------------------------------
			// BCrypt照合
			// -------------------------------------------------

			boolean matched =
					passwordEncoder.matches(
							candidate,
							passwordHash);

			// -------------------------------------------------
			// 突破成功
			//
			// 成功した場合は、
			// その回数の制限時間を加算しない。
			// -------------------------------------------------

			if (matched) {

				return new AttackResult(
						true,
						candidate,
						attemptCount,
						virtualWaitTimeMillis,
						false);
			}

			// =================================================
			// 失敗した場合の試行制限判定
			// =================================================

			if (attemptCount % WAIT_INTERVAL == 0) {

				restrictionCount++;

				// -------------------------------------------------
				// 5回目の制限
				//
				// 5000回失敗した時点で
				// 攻撃処理を強制終了する。
				//
				// 5回目には追加待機時間を加算しない。
				// -------------------------------------------------

				if (restrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					System.out.println(
							"========================================");

					System.out.println(
							"ランダムPassword攻撃を強制終了します。");

					System.out.println(
							"試行回数 = "
									+ attemptCount);

					System.out.println(
							"制限回数 = "
									+ restrictionCount);

					System.out.println(
							"強制終了条件 = "
									+ WAIT_INTERVAL
									+ "回 × "
									+ FORCE_TERMINATION_RESTRICTION_COUNT
									+ "回");

					System.out.println(
							"実際のユーザーアカウントはロックしません。");

					System.out.println(
							"========================================");

					return new AttackResult(
							false,
							null,
							attemptCount,
							virtualWaitTimeMillis,
							true);
				}

				// -------------------------------------------------
				// 1～4回目の制限
				// -------------------------------------------------

				long waitTime =
						WAIT_TIMES[
						           restrictionCount - 1];

				virtualWaitTimeMillis +=
						waitTime;

				System.out.println(
						"----------------------------------------");

				System.out.println(
						"ランダムPassword攻撃が"
								+ attemptCount
								+ "回失敗しました。");

				System.out.println(
						"制限回数 = "
								+ restrictionCount);

				System.out.println(
						"今回の仮想待機時間 = "
								+ formatWaitTime(
										waitTime));

				System.out.println(
						"累積仮想待機時間 = "
								+ formatWaitTime(
										virtualWaitTimeMillis));

				System.out.println(
						"※実際には待機しません。");

				System.out.println(
						"----------------------------------------");
			}
		}

		// =====================================================
		// 最大試行回数までに突破できなかった
		// =====================================================

		return new AttackResult(
				false,
				null,
				attemptCount,
				virtualWaitTimeMillis,
				false);
	}

	// =========================================================
	// 試行回数制限
	// =========================================================

	private int clampAttempts(
			int maxAttempts) {

		if (maxAttempts < 1) {

			return 1;
		}

		if (maxAttempts > TOTAL_PASSWORD_COUNT) {

			return TOTAL_PASSWORD_COUNT;
		}

		return maxAttempts;
	}

	// =========================================================
	// 待機時間表示
	// =========================================================

	private String formatWaitTime(
			long waitTimeMillis) {

		long minutes =
				waitTimeMillis / 60_000L;

		return minutes + "分";
	}

	// =========================================================
	// 攻撃結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String password;

		private final int attemptCount;

		/**
		 * 累積仮想待機時間
		 */
		private final long virtualWaitTimeMillis;

		/**
		 * 試行制限による強制終了
		 */
		private final boolean forceTerminated;

		// =====================================================
		// 既存コンストラクタ
		// =====================================================

		public AttackResult(
				boolean success,
				String password,
				int attemptCount) {

			this(
					success,
					password,
					attemptCount,
					0L,
					false);
		}

		// =====================================================
		// 仮想待機時間対応コンストラクタ
		// =====================================================

		public AttackResult(
				boolean success,
				String password,
				int attemptCount,
				long virtualWaitTimeMillis) {

			this(
					success,
					password,
					attemptCount,
					virtualWaitTimeMillis,
					false);
		}

		// =====================================================
		// 強制終了対応コンストラクタ
		// =====================================================

		public AttackResult(
				boolean success,
				String password,
				int attemptCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated) {

			this.success =
					success;

			this.password =
					password;

			this.attemptCount =
					attemptCount;

			this.virtualWaitTimeMillis =
					virtualWaitTimeMillis;

			this.forceTerminated =
					forceTerminated;
		}

		// =====================================================
		// Getter
		// =====================================================

		public boolean isSuccess() {

			return success;
		}

		public String getPassword() {

			return password;
		}

		public int getAttemptCount() {

			return attemptCount;
		}

		/**
		 * 累積仮想待機時間を取得する。
		 *
		 * 1回目の制限 = 1分
		 * 2回目の制限 = 5分
		 * 3回目の制限 = 10分
		 * 4回目の制限 = 20分
		 *
		 * 最大累積時間：
		 *
		 * 1 + 5 + 10 + 20
		 * = 36分
		 */
		public long getVirtualWaitTimeMillis() {

			return virtualWaitTimeMillis;
		}

		/**
		 * 試行制限によって
		 * 攻撃処理が強制終了されたかを取得する。
		 *
		 * true：
		 * 5000回失敗して強制終了
		 *
		 * false：
		 * 強制終了していない
		 */
		public boolean isForceTerminated() {

			return forceTerminated;
		}
	}
}