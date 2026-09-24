package com.example.attacksimulator.attack;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class MultiStagePasswordBruteForceAttack {

	private final PasswordEncoder passwordEncoder;

	public MultiStagePasswordBruteForceAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder = passwordEncoder;
	}

	// =========================================================
	// 一段階認証
	// Password
	// =========================================================

	public AttackResult executeOneStage(
			String passwordHash) {

		int attemptCount = 0;

		for (int i = 0; i <= 9999; i++) {

			String candidate =
					String.format("%04d", i);

			attemptCount++;

			System.out.println(
					"Stage 1 Attempt "
							+ attemptCount
							+ " : candidate="
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				System.out.println(
						"Password found: "
								+ candidate);

				return new AttackResult(
						true,
						1,
						attemptCount,
						candidate,
						null,
						null,
						"one-stage");
			}
		}

		return new AttackResult(
				false,
				1,
				attemptCount,
				null,
				null,
				null,
				"one-stage");
	}

	// =========================================================
	// 二段階認証
	// Password → Password2
	// =========================================================

	public AttackResult executeTwoStage(
			String passwordHash,
			String password2Hash) {

		int totalAttempts = 0;

		String password = null;
		String password2 = null;

		// -----------------------------------------------------
		// 第1段階 Password
		// -----------------------------------------------------

		for (int i = 0; i <= 9999; i++) {

			String candidate =
					String.format("%04d", i);

			totalAttempts++;

			System.out.println(
					"Stage 1 Attempt "
							+ totalAttempts
							+ " : candidate="
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				password = candidate;

				System.out.println(
						"Password found: "
								+ password);

				break;
			}
		}

		if (password == null) {

			return new AttackResult(
					false,
					2,
					totalAttempts,
					null,
					null,
					null,
					"two-stage");
		}

		// -----------------------------------------------------
		// 第2段階 Password2
		// -----------------------------------------------------

		int password2Attempts = 0;

		for (int i = 0; i <= 9999; i++) {

			String candidate =
					String.format("%04d", i);

			password2Attempts++;
			totalAttempts++;

			System.out.println(
					"Stage 2 Attempt "
							+ password2Attempts
							+ " : candidate="
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					password2Hash)) {

				password2 = candidate;

				System.out.println(
						"Password2 found: "
								+ password2);

				return new AttackResult(
						true,
						2,
						totalAttempts,
						password,
						password2,
						null,
						"two-stage");
			}
		}

		return new AttackResult(
				false,
				2,
				totalAttempts,
				password,
				null,
				null,
				"two-stage");
	}

	// =========================================================
	// 三段階認証
	// Password → Password2 → Password3
	// =========================================================

	public AttackResult executeThreeStage(
			String passwordHash,
			String password2Hash,
			String password3Hash) {

		int totalAttempts = 0;

		String password = null;
		String password2 = null;
		String password3 = null;

		// -----------------------------------------------------
		// 第1段階 Password
		// -----------------------------------------------------

		for (int i = 0; i <= 9999; i++) {

			String candidate =
					String.format("%04d", i);

			totalAttempts++;

			System.out.println(
					"Stage 1 Attempt "
							+ totalAttempts
							+ " : candidate="
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				password = candidate;

				System.out.println(
						"Password found: "
								+ password);

				break;
			}
		}

		if (password == null) {

			return new AttackResult(
					false,
					3,
					totalAttempts,
					null,
					null,
					null,
					"three-stage");
		}

		// -----------------------------------------------------
		// 第2段階 Password2
		// -----------------------------------------------------

		for (int i = 0; i <= 9999; i++) {

			String candidate =
					String.format("%04d", i);

			totalAttempts++;

			System.out.println(
					"Stage 2 Attempt "
							+ totalAttempts
							+ " : candidate="
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					password2Hash)) {

				password2 = candidate;

				System.out.println(
						"Password2 found: "
								+ password2);

				break;
			}
		}

		if (password2 == null) {

			return new AttackResult(
					false,
					3,
					totalAttempts,
					password,
					null,
					null,
					"three-stage");
		}

		// -----------------------------------------------------
		// 第3段階 Password3
		// -----------------------------------------------------

		for (int i = 0; i <= 9999; i++) {

			String candidate =
					String.format("%04d", i);

			totalAttempts++;

			System.out.println(
					"Stage 3 Attempt "
							+ totalAttempts
							+ " : candidate="
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					password3Hash)) {

				password3 = candidate;

				System.out.println(
						"Password3 found: "
								+ password3);

				return new AttackResult(
						true,
						3,
						totalAttempts,
						password,
						password2,
						password3,
						"three-stage");
			}
		}

		return new AttackResult(
				false,
				3,
				totalAttempts,
				password,
				password2,
				null,
				"three-stage");
	}

	// =========================================================
	// 結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final int stageCount;

		private final int totalAttempts;

		private final String password;

		private final String password2;

		private final String password3;

		private final String authMethod;

		public AttackResult(
				boolean success,
				int stageCount,
				int totalAttempts,
				String password,
				String password2,
				String password3,
				String authMethod) {

			this.success = success;
			this.stageCount = stageCount;
			this.totalAttempts = totalAttempts;
			this.password = password;
			this.password2 = password2;
			this.password3 = password3;
			this.authMethod = authMethod;
		}

		public boolean isSuccess() {
			return success;
		}

		public int getStageCount() {
			return stageCount;
		}

		public int getTotalAttempts() {
			return totalAttempts;
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

		public String getAuthMethod() {
			return authMethod;
		}
	}
}