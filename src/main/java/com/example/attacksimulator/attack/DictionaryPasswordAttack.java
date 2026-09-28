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
	// 二段階認証
	// Password → Password2
	//
	// Passwordを20個確認して一致したら、
	// Password2を20個確認する。
	//
	// 組み合わせ方式ではない。
	// 最大 100 + 100 = 200回
	// =========================================================

	public AttackResult executeTwoStage(
			int maxEntriesPassword,
			int maxEntriesPassword2,
			TwoStageVerifier verifier) {

		List<String> dictionaryPassword =
				DictionaryPasswordList.getPasswords(
						maxEntriesPassword);

		List<String> dictionaryPassword2 =
				DictionaryPasswordList.getPasswords(
						maxEntriesPassword2);

		int totalAttempts = 0;

		int passwordAttemptCount = 0;

		int password2AttemptCount = 0;

		String foundPassword = null;

		String foundPassword2 = null;

		// ---------------------------------------------------------
		// Passwordを確認
		// ---------------------------------------------------------

		for (String password : dictionaryPassword) {

			passwordAttemptCount++;
			totalAttempts++;

			boolean success =
					verifier.verify(
							1,
							password);

			if (success) {

				foundPassword = password;

				break;
			}
		}

		// Passwordが見つからなかった場合
		if (foundPassword == null) {

			return new AttackResult(
					2,
					false,
					null,
					null,
					null,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					0);
		}

		// ---------------------------------------------------------
		// Password2を確認
		// ---------------------------------------------------------

		for (String password2 : dictionaryPassword2) {

			password2AttemptCount++;
			totalAttempts++;

			boolean success =
					verifier.verify(
							2,
							password2);

			if (success) {

				foundPassword2 = password2;

				break;
			}
		}

		// Password2が見つからなかった場合
		if (foundPassword2 == null) {

			return new AttackResult(
					2,
					false,
					null,
					null,
					null,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					0);
		}

		// ---------------------------------------------------------
		// Password + Password2 両方成功
		// ---------------------------------------------------------

		return new AttackResult(
				2,
				true,
				foundPassword,
				foundPassword2,
				null,
				totalAttempts,
				passwordAttemptCount,
				password2AttemptCount,
				0);
	}

	// =========================================================
	// 三段階認証
	// Password → Password2 → Password3
	//
	// 各段階を独立して確認する。
	//
	// 最大 100 + 100 + 100 = 300回
	// =========================================================

	public AttackResult executeThreeStage(
			int maxEntriesPassword,
			int maxEntriesPassword2,
			int maxEntriesPassword3,
			ThreeStageVerifier verifier) {

		List<String> dictionaryPassword =
				DictionaryPasswordList.getPasswords(
						maxEntriesPassword);

		List<String> dictionaryPassword2 =
				DictionaryPasswordList.getPasswords(
						maxEntriesPassword2);

		List<String> dictionaryPassword3 =
				DictionaryPasswordList.getPasswords(
						maxEntriesPassword3);

		int totalAttempts = 0;

		int passwordAttemptCount = 0;

		int password2AttemptCount = 0;

		int password3AttemptCount = 0;

		String foundPassword = null;

		String foundPassword2 = null;

		String foundPassword3 = null;

		// ---------------------------------------------------------
		// Passwordを確認
		// ---------------------------------------------------------

		for (String password : dictionaryPassword) {

			passwordAttemptCount++;
			totalAttempts++;

			boolean success =
					verifier.verify(
							1,
							password);

			if (success) {

				foundPassword = password;

				break;
			}
		}

		// Passwordが見つからなかった場合
		if (foundPassword == null) {

			return new AttackResult(
					3,
					false,
					null,
					null,
					null,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					password3AttemptCount);
		}

		// ---------------------------------------------------------
		// Password2を確認
		// ---------------------------------------------------------

		for (String password2 : dictionaryPassword2) {

			password2AttemptCount++;
			totalAttempts++;

			boolean success =
					verifier.verify(
							2,
							password2);

			if (success) {

				foundPassword2 = password2;

				break;
			}
		}

		// Password2が見つからなかった場合
		if (foundPassword2 == null) {

			return new AttackResult(
					3,
					false,
					null,
					null,
					null,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					password3AttemptCount);
		}

		// ---------------------------------------------------------
		// Password3を確認
		// ---------------------------------------------------------

		for (String password3 : dictionaryPassword3) {

			password3AttemptCount++;
			totalAttempts++;

			boolean success =
					verifier.verify(
							3,
							password3);

			if (success) {

				foundPassword3 = password3;

				break;
			}
		}

		// Password3が見つからなかった場合
		if (foundPassword3 == null) {

			return new AttackResult(
					3,
					false,
					null,
					null,
					null,
					totalAttempts,
					passwordAttemptCount,
					password2AttemptCount,
					password3AttemptCount);
		}

		// ---------------------------------------------------------
		// Password + Password2 + Password3 全て成功
		// ---------------------------------------------------------

		return new AttackResult(
				3,
				true,
				foundPassword,
				foundPassword2,
				foundPassword3,
				totalAttempts,
				passwordAttemptCount,
				password2AttemptCount,
				password3AttemptCount);
	}

	// =========================================================
	// 一段階用
	// =========================================================

	@FunctionalInterface
	public interface PasswordVerifier {

		boolean verify(String password);
	}

	// =========================================================
	// 二段階用
	//
	// stage = 1 → Password
	// stage = 2 → Password2
	// =========================================================

	@FunctionalInterface
	public interface TwoStageVerifier {

		boolean verify(
				int stage,
				String password);
	}

	// =========================================================
	// 三段階用
	//
	// stage = 1 → Password
	// stage = 2 → Password2
	// stage = 3 → Password3
	// =========================================================

	@FunctionalInterface
	public interface ThreeStageVerifier {

		boolean verify(
				int stage,
				String password);
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