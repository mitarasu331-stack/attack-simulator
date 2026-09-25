package com.example.attacksimulator.attack;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordBruteForceAttack {

	private static final int PASSWORD_MIN = 0;
	private static final int PASSWORD_MAX = 9999;

	private final PasswordEncoder passwordEncoder;

	public PasswordBruteForceAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * 既存処理との互換用
	 * 最大10000回
	 */
	public AttackResult execute(String passwordHash) {

		return execute(passwordHash, 10000);
	}

	/**
	 * 最大試行回数を指定して総当たり
	 */
	public AttackResult execute(
			String passwordHash,
			int maxAttempts) {

		if (passwordHash == null
				|| passwordHash.isBlank()) {

			throw new IllegalArgumentException(
					"パスワードハッシュが指定されていません。");
		}

		if (maxAttempts <= 0) {

			throw new IllegalArgumentException(
					"最大試行回数は1以上にしてください。");
		}

		// パスワードは0000～9999なので
		// 最大でも10000回
		int actualMaxAttempts =
				Math.min(
						maxAttempts,
						PASSWORD_MAX - PASSWORD_MIN + 1);

		int attemptCount = 0;

		for (int i = PASSWORD_MIN;
				i <= PASSWORD_MAX;
				i++) {

			if (attemptCount >= actualMaxAttempts) {
				break;
			}

			String candidate =
					String.format("%04d", i);

			attemptCount++;

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				return new AttackResult(
						true,
						candidate,
						attemptCount);
			}
		}

		return new AttackResult(
				false,
				null,
				attemptCount);
	}

	public static class AttackResult {

		private final boolean success;
		private final String password;
		private final int attemptCount;

		public AttackResult(
				boolean success,
				String password,
				int attemptCount) {

			this.success = success;
			this.password = password;
			this.attemptCount = attemptCount;
		}

		public boolean isSuccess() {
			return success;
		}

		public String getPassword() {
			return password;
		}

		public int getAttemptCount() {
			return attemptCount;
		}
	}
}