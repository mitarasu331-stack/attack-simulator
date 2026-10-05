package com.example.attacksimulator.attack;

import java.util.List;

import org.springframework.stereotype.Component;

@Component
public class DictionaryPasswordAttack {

	// =========================================================
	// 一段階認証
	// =========================================================

	public AttackResult executeOneStage(
			int maxEntries,
			PasswordVerifier verifier) {

		List<String> dictionary =
				DictionaryPasswordList.getPasswords(maxEntries);

		int attemptCount = 0;

		for (String password : dictionary) {

			attemptCount++;

			boolean success =
					verifier.verify(password);

			if (success) {

				return new AttackResult(
						1,
						true,
						password,
						null,
						null,
						attemptCount,
						attemptCount,
						0,
						0);
			}
		}

		return new AttackResult(
				1,
				false,
				null,
				null,
				null,
				attemptCount,
				attemptCount,
				0,
				0);
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
					0);
		}

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
		}

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
	}
}