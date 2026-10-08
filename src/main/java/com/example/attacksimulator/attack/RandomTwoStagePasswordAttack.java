package com.example.attacksimulator.attack;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class RandomTwoStagePasswordAttack {

	private static final int MIN_PASSWORD = 0;

	private static final int MAX_PASSWORD = 9999;

	// =========================================================
	// 試行制限
	// =========================================================

	/**
	 * 1000回失敗するごとの仮想待機時間
	 *
	 * 実際には待機しない。
	 */
	private static final int WAIT_INTERVAL =
			1_000;

	/**
	 * 制限1回目
	 * 1000回失敗 → 1分
	 */
	private static final long WAIT_TIME_1 =
			60_000L;

	/**
	 * 制限2回目
	 * 2000回失敗 → 5分
	 */
	private static final long WAIT_TIME_2 =
			300_000L;

	/**
	 * 制限3回目
	 * 3000回失敗 → 10分
	 */
	private static final long WAIT_TIME_3 =
			600_000L;

	/**
	 * 制限4回目
	 * 4000回失敗 → 20分
	 */
	private static final long WAIT_TIME_4 =
			1_200_000L;

	/**
	 * 制限5回目
	 * 5000回失敗 → 30分
	 */
	private static final long WAIT_TIME_5 =
			1_800_000L;

	/**
	 * 制限6回目
	 * 6000回失敗 → 60分
	 */
	private static final long WAIT_TIME_6 =
			3_600_000L;

	/**
	 * 7回目の制限
	 *
	 * 7000回失敗した時点で
	 * 攻撃処理を強制終了する。
	 *
	 * 実際のアカウントはロックしない。
	 */
	private static final int FORCE_TERMINATION_RESTRICTION_COUNT =
			7;

	// =========================================================
	// PasswordEncoder
	// =========================================================

	private final PasswordEncoder passwordEncoder;

	/**
	 * 乱数生成器
	 */
	private final SecureRandom secureRandom =
			new SecureRandom();

	// =========================================================
	// コンストラクタ
	// =========================================================

	public RandomTwoStagePasswordAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder =
				passwordEncoder;
	}

	/**
	 * 二段階認証のランダム攻撃
	 *
	 * Stage 1 : Password
	 * Stage 2 : Password2
	 *
	 * 各段階で 0000 ～ 9999 を
	 * ランダムな順番で攻撃する。
	 *
	 * 同一段階内では
	 * 同じ値を二度攻撃しない。
	 *
	 * 1000回失敗するごとに
	 * 以下の仮想待機時間を加算する。
	 *
	 * 1000回  → 1分
	 * 2000回  → 5分
	 * 3000回  → 10分
	 * 4000回  → 20分
	 * 5000回  → 30分
	 * 6000回  → 60分
	 * 7000回  → 攻撃処理を強制終了
	 *
	 * 実際には待機しない。
	 */
	public AttackResult execute(
			String passwordHash,
			String password2Hash,
			int maxAttemptsPassword,
			int maxAttemptsPassword2) {

		// =====================================================
		// 攻撃回数を 1 ～ 10000 に制限
		// =====================================================

		maxAttemptsPassword =
				clampAttempts(
						maxAttemptsPassword);

		maxAttemptsPassword2 =
				clampAttempts(
						maxAttemptsPassword2);

		// =====================================================
		// 仮想待機時間
		// =====================================================

		long virtualWaitTimeMillis = 0L;

		// =====================================================
		// Stage 1 : Password
		// =====================================================

		List<String> passwordCandidates =
				createRandomCandidates();

		int passwordAttemptCount = 0;

		String password = null;

		int passwordRestrictionCount = 0;

		boolean forceTerminated = false;

		for (String candidate : passwordCandidates) {

			if (passwordAttemptCount
					>= maxAttemptsPassword) {

				break;
			}

			passwordAttemptCount++;

			// -------------------------------------------------
			// Password候補を1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					"ランダムPassword 試行 "
							+ passwordAttemptCount
							+ " / "
							+ maxAttemptsPassword
							+ " : "
							+ candidate);

			// -------------------------------------------------
			// BCrypt照合
			// -------------------------------------------------

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				password = candidate;

				break;
			}

			// -------------------------------------------------
			// 1000回失敗するごとの試行制限
			// -------------------------------------------------

			if (passwordAttemptCount % WAIT_INTERVAL == 0) {

				passwordRestrictionCount++;

				// ---------------------------------------------
				// 7回目の制限
				// 7000回失敗
				// ---------------------------------------------

				if (passwordRestrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					forceTerminated = true;

					System.out.println(
							"----------------------------------------");

					System.out.println(
							"ランダムPasswordが"
									+ passwordAttemptCount
									+ "回失敗しました。");

					System.out.println(
							"7回目の試行制限に到達したため、"
									+ "攻撃処理を強制終了します。");

					System.out.println(
							"実際のアカウントはロックしません。");

					System.out.println(
							"----------------------------------------");

					return new AttackResult(
							false,
							null,
							null,
							passwordAttemptCount,
							0,
							passwordAttemptCount,
							virtualWaitTimeMillis,
							true);
				}

				// ---------------------------------------------
				// 1～6回目の制限
				// ---------------------------------------------

				long waitTime =
						getWaitTime(
								passwordRestrictionCount);

				virtualWaitTimeMillis +=
						waitTime;

				System.out.println(
						"----------------------------------------");

				System.out.println(
						"ランダムPassword "
								+ passwordAttemptCount
								+ "回失敗");

				System.out.println(
						passwordRestrictionCount
								+ "回目の試行制限");

				System.out.println(
						"仮想待機時間 = "
								+ waitTime
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
		// Passwordが突破できなかった場合
		// Password2は攻撃しない
		// =====================================================

		if (password == null) {

			int totalAttemptCount =
					passwordAttemptCount;

			return new AttackResult(
					false,
					null,
					null,
					passwordAttemptCount,
					0,
					totalAttemptCount,
					virtualWaitTimeMillis,
					forceTerminated);
		}

		// =====================================================
		// Stage 2 : Password2
		// =====================================================

		List<String> password2Candidates =
				createRandomCandidates();

		int password2AttemptCount = 0;

		String password2 = null;

		int password2RestrictionCount = 0;

		for (String candidate : password2Candidates) {

			if (password2AttemptCount
					>= maxAttemptsPassword2) {

				break;
			}

			password2AttemptCount++;

			// -------------------------------------------------
			// Password2候補を1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					"ランダムPassword2 試行 "
							+ password2AttemptCount
							+ " / "
							+ maxAttemptsPassword2
							+ " : "
							+ candidate);

			// -------------------------------------------------
			// BCrypt照合
			// -------------------------------------------------

			if (passwordEncoder.matches(
					candidate,
					password2Hash)) {

				password2 = candidate;

				break;
			}

			// -------------------------------------------------
			// 1000回失敗するごとの試行制限
			// -------------------------------------------------

			if (password2AttemptCount
					% WAIT_INTERVAL == 0) {

				password2RestrictionCount++;

				// ---------------------------------------------
				// 7回目の制限
				// 7000回失敗
				// ---------------------------------------------

				if (password2RestrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					forceTerminated = true;

					System.out.println(
							"----------------------------------------");

					System.out.println(
							"ランダムPassword2が"
									+ password2AttemptCount
									+ "回失敗しました。");

					System.out.println(
							"7回目の試行制限に到達したため、"
									+ "攻撃処理を強制終了します。");

					System.out.println(
							"実際のアカウントはロックしません。");

					System.out.println(
							"----------------------------------------");

					int totalAttemptCount =
							passwordAttemptCount
							+ password2AttemptCount;

					return new AttackResult(
							false,
							password,
							null,
							passwordAttemptCount,
							password2AttemptCount,
							totalAttemptCount,
							virtualWaitTimeMillis,
							true);
				}

				// ---------------------------------------------
				// 1～6回目の制限
				// ---------------------------------------------

				long waitTime =
						getWaitTime(
								password2RestrictionCount);

				virtualWaitTimeMillis +=
						waitTime;

				System.out.println(
						"----------------------------------------");

				System.out.println(
						"ランダムPassword2 "
								+ password2AttemptCount
								+ "回失敗");

				System.out.println(
						password2RestrictionCount
								+ "回目の試行制限");

				System.out.println(
						"仮想待機時間 = "
								+ waitTime
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
		// 結果
		// =====================================================

		boolean success =
				password != null
				&& password2 != null;

		int totalAttemptCount =
				passwordAttemptCount
				+ password2AttemptCount;

		return new AttackResult(
				success,
				password,
				password2,
				passwordAttemptCount,
				password2AttemptCount,
				totalAttemptCount,
				virtualWaitTimeMillis,
				forceTerminated);
	}

	// =========================================================
	// 仮想待機時間取得
	// =========================================================

	private long getWaitTime(
			int restrictionCount) {

		switch (restrictionCount) {

		case 1:
			return WAIT_TIME_1;

		case 2:
			return WAIT_TIME_2;

		case 3:
			return WAIT_TIME_3;

		case 4:
			return WAIT_TIME_4;

		case 5:
			return WAIT_TIME_5;

		case 6:
			return WAIT_TIME_6;

		default:
			return 0L;
		}
	}

	/**
	 * 0000 ～ 9999 をランダムな順番で作成する
	 *
	 * 同じ段階内では重複しない。
	 */
	private List<String> createRandomCandidates() {

		List<String> candidates =
				new ArrayList<>(10_000);

		for (int i = MIN_PASSWORD;
				i <= MAX_PASSWORD;
				i++) {

			candidates.add(
					String.format(
							"%04d",
							i));
		}

		Collections.shuffle(
				candidates,
				secureRandom);

		return candidates;
	}

	/**
	 * 攻撃回数を 1 ～ 10000 に制限
	 */
	private int clampAttempts(
			int attempts) {

		if (attempts < 1) {

			return 1;
		}

		if (attempts > 10_000) {

			return 10_000;
		}

		return attempts;
	}

	/**
	 * ランダム攻撃結果
	 */
	public static class AttackResult {

		private final boolean success;

		private final String password;

		private final String password2;

		private final int passwordAttemptCount;

		private final int password2AttemptCount;

		private final int attemptCount;

		// 実際には待機していない仮想待機時間
		private final long virtualWaitTimeMillis;

		// 試行制限によって攻撃処理を強制終了したか
		private final boolean forceTerminated;

		// =====================================================
		// コンストラクタ
		// =====================================================

		public AttackResult(
				boolean success,
				String password,
				String password2,
				int passwordAttemptCount,
				int password2AttemptCount,
				int attemptCount,
				long virtualWaitTimeMillis) {

			this(
					success,
					password,
					password2,
					passwordAttemptCount,
					password2AttemptCount,
					attemptCount,
					virtualWaitTimeMillis,
					false);
		}

		// =====================================================
		// forceTerminated対応コンストラクタ
		// =====================================================

		public AttackResult(
				boolean success,
				String password,
				String password2,
				int passwordAttemptCount,
				int password2AttemptCount,
				int attemptCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated) {

			this.success =
					success;

			this.password =
					password;

			this.password2 =
					password2;

			this.passwordAttemptCount =
					passwordAttemptCount;

			this.password2AttemptCount =
					password2AttemptCount;

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

		public String getPassword2() {

			return password2;
		}

		public int getPasswordAttemptCount() {

			return passwordAttemptCount;
		}

		public int getPassword2AttemptCount() {

			return password2AttemptCount;
		}

		public int getAttemptCount() {

			return attemptCount;
		}

		/**
		 * 実際には待っていないが、
		 * 攻撃時間として加算する待機時間
		 */
		public long getVirtualWaitTimeMillis() {

			return virtualWaitTimeMillis;
		}

		/**
		 * 試行制限によって
		 * 攻撃処理を強制終了したか
		 */
		public boolean isForceTerminated() {

			return forceTerminated;
		}
	}
}