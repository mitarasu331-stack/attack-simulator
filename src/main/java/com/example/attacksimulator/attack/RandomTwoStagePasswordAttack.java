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

	// 1000回失敗するごとに、本来待つ時間として60秒を加算
	private static final long WAIT_TIME_MILLIS = 60_000L;

	private final PasswordEncoder passwordEncoder;
	private final SecureRandom secureRandom = new SecureRandom();

	public RandomTwoStagePasswordAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * 二段階認証のランダム攻撃
	 *
	 * Stage 1 : Password
	 * Stage 2 : Password2
	 *
	 * 各段階で 0000 ～ 9999 をランダムな順番で攻撃する。
	 * 同一段階内では同じ値を二度攻撃しない。
	 *
	 * 1000回失敗するごとに、実際には待機せず
	 * 待機した時間を virtualWaitTimeMillis に加算する。
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
				clampAttempts(maxAttemptsPassword);

		maxAttemptsPassword2 =
				clampAttempts(maxAttemptsPassword2);

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

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				password = candidate;

				break;
			}

			// -------------------------------------------------
			// 1000回失敗するごとに
			// 実際には待たず、60秒を加算
			// -------------------------------------------------

			if (passwordAttemptCount % 1000 == 0
					&& passwordAttemptCount
							< maxAttemptsPassword) {

				virtualWaitTimeMillis +=
						WAIT_TIME_MILLIS;

				System.out.println(
						"ランダムPassword "
								+ passwordAttemptCount
								+ "回失敗"
								+ " → 仮想待機時間 "
								+ WAIT_TIME_MILLIS
								+ " ms を加算");

				System.out.println(
						"累積仮想待機時間 = "
								+ virtualWaitTimeMillis
								+ " ms");
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
					virtualWaitTimeMillis);
		}

		// =====================================================
		// Stage 2 : Password2
		// =====================================================

		List<String> password2Candidates =
				createRandomCandidates();

		int password2AttemptCount = 0;

		String password2 = null;

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

			if (passwordEncoder.matches(
					candidate,
					password2Hash)) {

				password2 = candidate;

				break;
			}

			// -------------------------------------------------
			// 1000回失敗するごとに
			// 実際には待たず、60秒を加算
			// -------------------------------------------------

			if (password2AttemptCount % 1000 == 0
					&& password2AttemptCount
							< maxAttemptsPassword2) {

				virtualWaitTimeMillis +=
						WAIT_TIME_MILLIS;

				System.out.println(
						"ランダムPassword2 "
								+ password2AttemptCount
								+ "回失敗"
								+ " → 仮想待機時間 "
								+ WAIT_TIME_MILLIS
								+ " ms を加算");

				System.out.println(
						"累積仮想待機時間 = "
								+ virtualWaitTimeMillis
								+ " ms");
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
				virtualWaitTimeMillis);
	}

	/**
	 * 0000 ～ 9999 をランダムな順番で作成する
	 *
	 * 同じ段階内では重複しない。
	 */
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

	/**
	 * 攻撃回数を 1 ～ 10000 に制限
	 */
	private int clampAttempts(int attempts) {

		if (attempts < 1) {

			return 1;
		}

		if (attempts > 10000) {

			return 10000;
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

		public AttackResult(
				boolean success,
				String password,
				String password2,
				int passwordAttemptCount,
				int password2AttemptCount,
				int attemptCount,
				long virtualWaitTimeMillis) {

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
	}
}