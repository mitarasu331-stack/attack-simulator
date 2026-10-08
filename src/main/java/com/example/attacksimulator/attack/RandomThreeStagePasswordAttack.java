package com.example.attacksimulator.attack;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class RandomThreeStagePasswordAttack {

	private static final int MIN_PASSWORD = 0;

	private static final int MAX_PASSWORD = 9999;

	// =========================================================
	// 仮想待機時間
	// =========================================================

	/**
	 * 1000回失敗ごとの制限回数
	 */
	private static final int WAIT_INTERVAL =
			1_000;

	/**
	 * 制限ごとの仮想待機時間
	 *
	 * 1回目   → 1分
	 * 2回目   → 5分
	 * 3回目   → 10分
	 * 4回目   → 20分
	 */
	private static final long[] WAIT_TIMES = {
			60_000L,
			300_000L,
			600_000L,
			1_200_000L
	};

	/**
	 * 5回目の制限到達時に
	 * 攻撃処理を強制終了する
	 *
	 * 5000回失敗
	 */
	private static final int FORCE_TERMINATION_RESTRICTION_COUNT =
			5;

	private final PasswordEncoder passwordEncoder;

	private final SecureRandom secureRandom =
			new SecureRandom();

	public RandomThreeStagePasswordAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder =
				passwordEncoder;
	}

	// =========================================================
	// 三段階認証 ランダム攻撃
	//
	// Password
	//     ↓
	// Password2
	//     ↓
	// Password3
	// =========================================================

	public AttackResult execute(
			String passwordHash,
			String password2Hash,
			String password3Hash,
			int maxAttemptsPassword,
			int maxAttemptsPassword2,
			int maxAttemptsPassword3) {

		maxAttemptsPassword =
				clampAttempts(
						maxAttemptsPassword);

		maxAttemptsPassword2 =
				clampAttempts(
						maxAttemptsPassword2);

		maxAttemptsPassword3 =
				clampAttempts(
						maxAttemptsPassword3);

		// =====================================================
		// Stage 1
		// Password
		// =====================================================

		List<String> passwordCandidates =
				createRandomCandidates();

		int passwordAttemptCount = 0;

		String password = null;

		long passwordVirtualWaitTime =
				0L;

		int passwordRestrictionCount =
				0;

		boolean passwordForceTerminated =
				false;

		for (String candidate :
			passwordCandidates) {

			if (passwordAttemptCount
					>= maxAttemptsPassword) {

				break;
			}

			passwordAttemptCount++;

			// -------------------------------------------------
			// Password候補は1件ずつ表示
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
			//
			// 成功した場合は、
			// その回の制限処理を行わない。
			// -------------------------------------------------

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				password = candidate;

				break;
			}

			// -------------------------------------------------
			// 1000回失敗するごとの制限
			// -------------------------------------------------

			if (passwordAttemptCount
					% WAIT_INTERVAL == 0) {

				passwordRestrictionCount++;

				// -------------------------------------------------
				// 5回目の制限
				//
				// 5000回失敗
				// → 攻撃処理を強制終了
				//
				// 待機時間は追加しない。
				// -------------------------------------------------

				if (passwordRestrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					passwordForceTerminated =
							true;

					System.out.println(
							"ランダムPassword "
									+ passwordAttemptCount
									+ "回失敗"
									+ " → 試行制限により攻撃処理を強制終了");

					break;
				}

				// -------------------------------------------------
				// 1～4回目の制限
				// -------------------------------------------------

				long waitTime =
						WAIT_TIMES[
						           passwordRestrictionCount - 1];

				passwordVirtualWaitTime +=
						waitTime;

				System.out.println(
						"ランダムPassword "
								+ passwordAttemptCount
								+ "回失敗"
								+ " → 仮想待機時間 "
								+ waitTime
								+ " ms を加算");

				System.out.println(
						"Password 累積仮想待機時間 = "
								+ passwordVirtualWaitTime
								+ " ms");
			}
		}

		// =====================================================
		// Password強制終了
		// =====================================================

		if (passwordForceTerminated) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					passwordAttemptCount,
					0,
					0,
					passwordAttemptCount,
					passwordVirtualWaitTime,
					true);
		}

		// =====================================================
		// Password失敗
		// =====================================================

		if (password == null) {

			return new AttackResult(
					false,
					null,
					null,
					null,
					passwordAttemptCount,
					0,
					0,
					passwordAttemptCount,
					passwordVirtualWaitTime,
					false);
		}

		// =====================================================
		// Stage 2
		// Password2
		// =====================================================

		List<String> password2Candidates =
				createRandomCandidates();

		int password2AttemptCount = 0;

		String password2 = null;

		long password2VirtualWaitTime =
				0L;

		int password2RestrictionCount =
				0;

		boolean password2ForceTerminated =
				false;

		for (String candidate :
			password2Candidates) {

			if (password2AttemptCount
					>= maxAttemptsPassword2) {

				break;
			}

			password2AttemptCount++;

			// -------------------------------------------------
			// Password2候補は1件ずつ表示
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
			// 1000回失敗するごとの制限
			// -------------------------------------------------

			if (password2AttemptCount
					% WAIT_INTERVAL == 0) {

				password2RestrictionCount++;

				// -------------------------------------------------
				// 5回目の制限
				// → 5000回失敗で強制終了
				// -------------------------------------------------

				if (password2RestrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					password2ForceTerminated =
							true;

					System.out.println(
							"ランダムPassword2 "
									+ password2AttemptCount
									+ "回失敗"
									+ " → 試行制限により攻撃処理を強制終了");

					break;
				}

				// -------------------------------------------------
				// 1～4回目の制限
				// -------------------------------------------------

				long waitTime =
						WAIT_TIMES[
						           password2RestrictionCount - 1];

				password2VirtualWaitTime +=
						waitTime;

				System.out.println(
						"ランダムPassword2 "
								+ password2AttemptCount
								+ "回失敗"
								+ " → 仮想待機時間 "
								+ waitTime
								+ " ms を加算");

				System.out.println(
						"Password2 累積仮想待機時間 = "
								+ password2VirtualWaitTime
								+ " ms");
			}
		}

		// =====================================================
		// Password2強制終了
		// =====================================================

		if (password2ForceTerminated) {

			long virtualWaitTimeMillis =
					passwordVirtualWaitTime
					+ password2VirtualWaitTime;

			int totalAttemptCount =
					passwordAttemptCount
					+ password2AttemptCount;

			return new AttackResult(
					false,
					password,
					null,
					null,
					passwordAttemptCount,
					password2AttemptCount,
					0,
					totalAttemptCount,
					virtualWaitTimeMillis,
					true);
		}

		// =====================================================
		// Password2失敗
		// =====================================================

		if (password2 == null) {

			long virtualWaitTimeMillis =
					passwordVirtualWaitTime
					+ password2VirtualWaitTime;

			int totalAttemptCount =
					passwordAttemptCount
					+ password2AttemptCount;

			return new AttackResult(
					false,
					password,
					null,
					null,
					passwordAttemptCount,
					password2AttemptCount,
					0,
					totalAttemptCount,
					virtualWaitTimeMillis,
					false);
		}

		// =====================================================
		// Stage 3
		// Password3
		// =====================================================

		List<String> password3Candidates =
				createRandomCandidates();

		int password3AttemptCount = 0;

		String password3 = null;

		long password3VirtualWaitTime =
				0L;

		int password3RestrictionCount =
				0;

		boolean password3ForceTerminated =
				false;

		for (String candidate :
			password3Candidates) {

			if (password3AttemptCount
					>= maxAttemptsPassword3) {

				break;
			}

			password3AttemptCount++;

			// -------------------------------------------------
			// Password3候補は1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					"ランダムPassword3 試行 "
							+ password3AttemptCount
							+ " / "
							+ maxAttemptsPassword3
							+ " : "
							+ candidate);

			// -------------------------------------------------
			// BCrypt照合
			// -------------------------------------------------

			if (passwordEncoder.matches(
					candidate,
					password3Hash)) {

				password3 = candidate;

				break;
			}

			// -------------------------------------------------
			// 1000回失敗するごとの制限
			// -------------------------------------------------

			if (password3AttemptCount
					% WAIT_INTERVAL == 0) {

				password3RestrictionCount++;

				// -------------------------------------------------
				// 5回目の制限
				// → 5000回失敗で強制終了
				// -------------------------------------------------

				if (password3RestrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					password3ForceTerminated =
							true;

					System.out.println(
							"ランダムPassword3 "
									+ password3AttemptCount
									+ "回失敗"
									+ " → 試行制限により攻撃処理を強制終了");

					break;
				}

				// -------------------------------------------------
				// 1～4回目の制限
				// -------------------------------------------------

				long waitTime =
						WAIT_TIMES[
						           password3RestrictionCount - 1];

				password3VirtualWaitTime +=
						waitTime;

				System.out.println(
						"ランダムPassword3 "
								+ password3AttemptCount
								+ "回失敗"
								+ " → 仮想待機時間 "
								+ waitTime
								+ " ms を加算");

				System.out.println(
						"Password3 累積仮想待機時間 = "
								+ password3VirtualWaitTime
								+ " ms");
			}
		}

		// =====================================================
		// Password3強制終了
		// =====================================================

		if (password3ForceTerminated) {

			long virtualWaitTimeMillis =
					passwordVirtualWaitTime
					+ password2VirtualWaitTime
					+ password3VirtualWaitTime;

			int totalAttemptCount =
					passwordAttemptCount
					+ password2AttemptCount
					+ password3AttemptCount;

			return new AttackResult(
					false,
					password,
					password2,
					null,
					passwordAttemptCount,
					password2AttemptCount,
					password3AttemptCount,
					totalAttemptCount,
					virtualWaitTimeMillis,
					true);
		}

		// =====================================================
		// 最終結果
		// =====================================================

		boolean success =
				password != null
				&& password2 != null
				&& password3 != null;

		int totalAttemptCount =
				passwordAttemptCount
				+ password2AttemptCount
				+ password3AttemptCount;

		long virtualWaitTimeMillis =
				passwordVirtualWaitTime
				+ password2VirtualWaitTime
				+ password3VirtualWaitTime;

		System.out.println(
				"三段階認証 累積仮想待機時間 = "
						+ virtualWaitTimeMillis
						+ " ms");

		return new AttackResult(
				success,
				password,
				password2,
				password3,
				passwordAttemptCount,
				password2AttemptCount,
				password3AttemptCount,
				totalAttemptCount,
				virtualWaitTimeMillis,
				false);
	}

	// =========================================================
	// 0000～9999をランダムな順番で作成
	// =========================================================

	private List<String> createRandomCandidates() {

		List<String> candidates =
				new ArrayList<>(10000);

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

	// =========================================================
	// 試行回数制限
	// =========================================================

	private int clampAttempts(
			int attempts) {

		if (attempts < 1) {

			return 1;
		}

		if (attempts > 10000) {

			return 10000;
		}

		return attempts;
	}

	// =========================================================
	// 攻撃結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String password;

		private final String password2;

		private final String password3;

		private final int passwordAttemptCount;

		private final int password2AttemptCount;

		private final int password3AttemptCount;

		private final int attemptCount;

		/**
		 * 実際には待機していないが、
		 * 攻撃時間として加算する仮想待機時間
		 */
		private final long virtualWaitTimeMillis;

		/**
		 * 試行制限によって攻撃処理を
		 * 強制終了したか
		 */
		private final boolean forceTerminated;

		public AttackResult(
				boolean success,
				String password,
				String password2,
				String password3,
				int passwordAttemptCount,
				int password2AttemptCount,
				int password3AttemptCount,
				int attemptCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated) {

			this.success =
					success;

			this.password =
					password;

			this.password2 =
					password2;

			this.password3 =
					password3;

			this.passwordAttemptCount =
					passwordAttemptCount;

			this.password2AttemptCount =
					password2AttemptCount;

			this.password3AttemptCount =
					password3AttemptCount;

			this.attemptCount =
					attemptCount;

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

		public int getPasswordAttemptCount() {

			return passwordAttemptCount;
		}

		public int getPassword2AttemptCount() {

			return password2AttemptCount;
		}

		public int getPassword3AttemptCount() {

			return password3AttemptCount;
		}

		public int getAttemptCount() {

			return attemptCount;
		}

		/**
		 * 実際には待っていないが、
		 * 攻撃時間として加算する仮想待機時間
		 *
		 * 1段階あたりの最大累積時間：
		 *
		 * 1 + 5 + 10 + 20
		 * = 36分
		 *
		 * 三段階すべてで最大まで制限された場合：
		 *
		 * 36 + 36 + 36
		 * = 108分
		 */
		public long getVirtualWaitTimeMillis() {

			return virtualWaitTimeMillis;
		}

		/**
		 * 試行制限によって
		 * 攻撃処理を強制終了したか
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