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

		System.out.println(
				"========================================");

		System.out.println(
				"三段階認証 ランダム攻撃開始");

		System.out.println(
				"Password 最大試行回数 = "
						+ maxAttemptsPassword);

		System.out.println(
				"Password2 最大試行回数 = "
						+ maxAttemptsPassword2);

		System.out.println(
				"Password3 最大試行回数 = "
						+ maxAttemptsPassword3);

		System.out.println(
				"========================================");

		// =====================================================
		// Stage 1
		// Password
		// =====================================================

		List<String> passwordCandidates =
				createRandomCandidates();

		int passwordAttemptCount = 0;

		String password = null;

		for (String candidate :
			passwordCandidates) {

			if (passwordAttemptCount
					>= maxAttemptsPassword) {

				break;
			}

			passwordAttemptCount++;

			System.out.println(
					"Password 試行 "
							+ passwordAttemptCount
							+ " / "
							+ maxAttemptsPassword
							+ " : "
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				password = candidate;

				System.out.println(
						"Password 攻撃成功");

				System.out.println(
						"Password = "
								+ password);

				System.out.println(
						"Password 試行回数 = "
								+ passwordAttemptCount);

				break;
			}
		}

		// =====================================================
		// Password失敗
		// =====================================================

		if (password == null) {

			System.out.println(
					"Password 攻撃失敗");

			System.out.println(
					"Password2 は攻撃しません");

			System.out.println(
					"Password3 は攻撃しません");

			System.out.println(
					"総攻撃試行回数 = "
							+ passwordAttemptCount);

			System.out.println(
					"========================================");

			return new AttackResult(
					false,
					null,
					null,
					null,
					passwordAttemptCount,
					0,
					0,
					passwordAttemptCount);
		}

		// =====================================================
		// Stage 2
		// Password2
		// =====================================================

		List<String> password2Candidates =
				createRandomCandidates();

		int password2AttemptCount = 0;

		String password2 = null;

		for (String candidate :
			password2Candidates) {

			if (password2AttemptCount
					>= maxAttemptsPassword2) {

				break;
			}

			password2AttemptCount++;

			System.out.println(
					"Password2 試行 "
							+ password2AttemptCount
							+ " / "
							+ maxAttemptsPassword2
							+ " : "
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					password2Hash)) {

				password2 = candidate;

				System.out.println(
						"Password2 攻撃成功");

				System.out.println(
						"Password2 = "
								+ password2);

				System.out.println(
						"Password2 試行回数 = "
								+ password2AttemptCount);

				break;
			}
		}

		// =====================================================
		// Password2失敗
		// =====================================================

		if (password2 == null) {

			int totalAttemptCount =
					passwordAttemptCount
					+ password2AttemptCount;

			System.out.println(
					"Password2 攻撃失敗");

			System.out.println(
					"Password3 は攻撃しません");

			System.out.println(
					"総攻撃試行回数 = "
							+ totalAttemptCount);

			System.out.println(
					"========================================");

			return new AttackResult(
					false,
					password,
					null,
					null,
					passwordAttemptCount,
					password2AttemptCount,
					0,
					totalAttemptCount);
		}

		// =====================================================
		// Stage 3
		// Password3
		// =====================================================

		List<String> password3Candidates =
				createRandomCandidates();

		int password3AttemptCount = 0;

		String password3 = null;

		for (String candidate :
			password3Candidates) {

			if (password3AttemptCount
					>= maxAttemptsPassword3) {

				break;
			}

			password3AttemptCount++;

			System.out.println(
					"Password3 試行 "
							+ password3AttemptCount
							+ " / "
							+ maxAttemptsPassword3
							+ " : "
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					password3Hash)) {

				password3 = candidate;

				System.out.println(
						"Password3 攻撃成功");

				System.out.println(
						"Password3 = "
								+ password3);

				System.out.println(
						"Password3 試行回数 = "
								+ password3AttemptCount);

				break;
			}
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

		if (success) {

			System.out.println(
					"三段階認証ランダム攻撃成功");

			System.out.println(
					"Password = "
							+ password);

			System.out.println(
					"Password2 = "
							+ password2);

			System.out.println(
					"Password3 = "
							+ password3);

		} else {

			System.out.println(
					"三段階認証ランダム攻撃失敗");

			if (password3 == null) {

				System.out.println(
						"Password3 が突破できませんでした");
			}
		}

		System.out.println(
				"Password 試行回数 = "
						+ passwordAttemptCount);

		System.out.println(
				"Password2 試行回数 = "
						+ password2AttemptCount);

		System.out.println(
				"Password3 試行回数 = "
						+ password3AttemptCount);

		System.out.println(
				"総攻撃試行回数 = "
						+ totalAttemptCount);

		System.out.println(
				"========================================");

		return new AttackResult(
				success,
				password,
				password2,
				password3,
				passwordAttemptCount,
				password2AttemptCount,
				password3AttemptCount,
				totalAttemptCount);
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

		public AttackResult(
				boolean success,
				String password,
				String password2,
				String password3,
				int passwordAttemptCount,
				int password2AttemptCount,
				int password3AttemptCount,
				int attemptCount) {

			this.success = success;

			this.password = password;

			this.password2 = password2;

			this.password3 = password3;

			this.passwordAttemptCount =
					passwordAttemptCount;

			this.password2AttemptCount =
					password2AttemptCount;

			this.password3AttemptCount =
					password3AttemptCount;

			this.attemptCount =
					attemptCount;
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
	}
}