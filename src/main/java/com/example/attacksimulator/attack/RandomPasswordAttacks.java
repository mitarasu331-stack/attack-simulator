package com.example.attacksimulator.attack;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class RandomPasswordAttacks {

	private final FactorAuthenticationAttack factorAuthenticationAttack;
	private static final int MIN_PASSWORD = 0;

	private static final int MAX_PASSWORD = 9999;

	/**
	 * 1000回失敗ごとの制限回数
	 */
	private static final int WAIT_INTERVAL = 1_000;

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
			1_200_000L,
	};

	/**
	 * 5回目の制限到達時に
	 * 攻撃処理を強制終了する
	 *
	 * 5000回失敗
	 */
	private static final int FORCE_TERMINATION_RESTRICTION_COUNT = 5;

	private final PasswordEncoder passwordEncoder;

	private final SecureRandom secureRandom = new SecureRandom();

	public RandomPasswordAttacks(
			PasswordEncoder passwordEncoder, FactorAuthenticationAttack factorAuthenticationAttack) {

		this.passwordEncoder = passwordEncoder;

		this.factorAuthenticationAttack = factorAuthenticationAttack;
	}

	// =========================================================
	// ??段階認証 ランダム攻撃
	//
	// Password
	//     ↓
	// Password2
	//     ↓
	// Password3
	// =========================================================

	public AttackResult execute(
			String[] passwordHash,
			int[] maxAttemptsPasswords, int maxpassword) {

		//maxpassword が１以上３未満じゃないかの確認
		if (maxpassword < 1 || maxpassword > 3
				|| passwordHash == null
				|| maxAttemptsPasswords == null
				|| passwordHash.length < maxpassword
				|| maxAttemptsPasswords.length < maxpassword) {

			throw new IllegalArgumentException(
					"認証段階数または配列が不正です。");
		}
		for (int i = 0; i < maxpassword; i++) {
			maxAttemptsPasswords[i] = clampAttempts(
					maxAttemptsPasswords[i]);
		}

		String[] password = new String[maxpassword];
		int[] passwordAttemptCount = new int[maxpassword];
		long[] passwordVirtualWaitTime = new long[maxpassword];
		int[] passwordRestrictionCount = new int[maxpassword];
		// =====================================================
		// 一段階認証
		// =====================================================
		for (int i = 0; i < maxpassword; i++) {
			List<String> passwordCandidates = createRandomCandidates();
			passwordAttemptCount[i] = 0;
			passwordVirtualWaitTime[i] = 0L;
			passwordRestrictionCount[i] = 0;

			boolean passwordForceTerminated = false;

			for (String candidate : passwordCandidates) {

				if (passwordAttemptCount[i] >= maxAttemptsPasswords[i]) {

					break;
				}

				passwordAttemptCount[i]++;

				// -------------------------------------------------
				// Password候補は1件ずつ表示
				// -------------------------------------------------
				System.out.println(

						"ランダムPassword 試行 "

								+ passwordAttemptCount[i]

								+ " / "

								+ maxAttemptsPasswords[i]

								+ " : "

								+ candidate);

				// -------------------------------------------------
				// BCrypt照合
				// -------------------------------------------------

				if (passwordEncoder.matches(
						candidate,
						passwordHash[i])) {

					password[i] = candidate;

					break;
				}

				// -------------------------------------------------
				// 1000回失敗するごとの制限
				// -------------------------------------------------

				if (passwordAttemptCount[i]
						% WAIT_INTERVAL == 0) {

					passwordRestrictionCount[i]++;

					// -------------------------------------------------
					// 5回目の制限
					//
					// 5000回失敗
					// → 攻撃処理を強制終了
					//
					// 待機時間は追加しない。
					// -------------------------------------------------

					if (passwordRestrictionCount[i] >= FORCE_TERMINATION_RESTRICTION_COUNT) {

						passwordForceTerminated = true;

						System.out.println("===========================================");
						System.out.println(passwordAttemptCount[i] + "回失敗");
						System.out.println("===========================================");

						break;
					}

					// -------------------------------------------------
					// 1～4回目の制限
					// -------------------------------------------------

					long waitTime = WAIT_TIMES[passwordRestrictionCount[i] - 1];

					passwordVirtualWaitTime[i] += waitTime;

					System.out.println("===========================================");
					System.out.println(passwordAttemptCount[i]
							+ "回失敗"
							+ " → 仮想待機時間 "
							+ waitTime
							+ " ms を加算");

					System.out.println(
							"Password 累積仮想待機時間 = "
									+ passwordVirtualWaitTime[i] + " ms");
					System.out.println("===========================================");

				}
			}

			// =====================================================
			// Password強制終了
			// =====================================================
			if (passwordForceTerminated) {

				return createResult(
						false,
						password,
						passwordAttemptCount,
						passwordVirtualWaitTime,
						true);
			}

			// =====================================================
			// Password失敗
			// =====================================================

			if (password[i] == null) {

				if (password[i] == null) {

					return createResult(
							false,
							password,
							passwordAttemptCount,
							passwordVirtualWaitTime,
							false);
				}
			}
		}

		// =====================================================
		// 最終結果
		// =====================================================

		boolean success = true;
		int totalAttemptCount = 0;
		long virtualWaitTimeMillis = 0L;

		for (int i = 0; i < maxpassword; i++) {
			if (password[i] == null) {
				success = false;
			}
			totalAttemptCount += passwordAttemptCount[i];
			virtualWaitTimeMillis += passwordVirtualWaitTime[i];
		}

		switch (maxpassword) {
		case 1:
			return new AttackResult(
					success,
					password[0],
					null,
					null,
					passwordAttemptCount[0],
					0,
					0,
					totalAttemptCount,
					virtualWaitTimeMillis,
					false);
		case 2:
			return new AttackResult(
					success,
					password[0],
					password[1],
					null,
					passwordAttemptCount[0],
					passwordAttemptCount[1],
					0,
					totalAttemptCount,
					virtualWaitTimeMillis,
					false);
		case 3:
			return new AttackResult(
					success,
					password[0],
					password[1],
					password[2],
					passwordAttemptCount[0],
					passwordAttemptCount[1],
					passwordAttemptCount[2],
					totalAttemptCount,
					virtualWaitTimeMillis,
					false);
		default:
			throw new IllegalArgumentException(
					"対応していない認証段階数です。");
		}

	}

	// =========================================================
	// 0000～9999をランダムな順番で作成
	// =========================================================

	private List<String> createRandomCandidates() {

		List<String> candidates = new ArrayList<>(10000);

		for (int i = MIN_PASSWORD; i <= MAX_PASSWORD; i++) {

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

		private final long virtualWaitTimeMillis;

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

			this.success = success;

			this.password = password;

			this.password2 = password2;

			this.password3 = password3;

			this.passwordAttemptCount = passwordAttemptCount;

			this.password2AttemptCount = password2AttemptCount;

			this.password3AttemptCount = password3AttemptCount;

			this.attemptCount = attemptCount;

			this.virtualWaitTimeMillis = virtualWaitTimeMillis;

			this.forceTerminated = forceTerminated;
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

		public long getVirtualWaitTimeMillis() {

			return virtualWaitTimeMillis;
		}

		public boolean isForceTerminated() {

			return forceTerminated;
		}
	}

	private AttackResult createResult(
			boolean success,
			String[] password,
			int[] passwordAttemptCount,
			long[] passwordVirtualWaitTime,
			boolean forceTerminated) {

		int totalAttemptCount = 0;
		long totalVirtualWaitTime = 0L;

		for (int i = 0; i < password.length; i++) {
			totalAttemptCount += passwordAttemptCount[i];
			totalVirtualWaitTime += passwordVirtualWaitTime[i];
		}

		return new AttackResult(
				success,
				password.length > 0 ? password[0] : null,
				password.length > 1 ? password[1] : null,
				password.length > 2 ? password[2] : null,
				passwordAttemptCount.length > 0
						? passwordAttemptCount[0]
						: 0,
				passwordAttemptCount.length > 1
						? passwordAttemptCount[1]
						: 0,
				passwordAttemptCount.length > 2
						? passwordAttemptCount[2]
						: 0,
				totalAttemptCount,
				totalVirtualWaitTime,
				forceTerminated);
	}
}
