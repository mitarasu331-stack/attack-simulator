package com.example.attacksimulator.attack;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordBruteForceAttack {

	private static final int PASSWORD_MIN = 0;
	private static final int PASSWORD_MAX = 9999;

	/**
	 * 1000回ごとの仮想待機時間
	 *
	 * 実際には待機しない。
	 *
	 * 60秒 = 60000ms
	 */
	private static final long WAIT_TIME_MILLIS =
			60_000L;

	private static final int WAIT_INTERVAL =
			1_000;

	private final PasswordEncoder passwordEncoder;

	public PasswordBruteForceAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * 既存処理との互換用
	 * 最大10000回
	 */
	public AttackResult execute(
			String passwordHash) {

		return execute(
				passwordHash,
				10000);
	}

	/**
	 * 最大試行回数を指定して総当たり
	 *
	 * 実際には待機せず連続して試行する。
	 *
	 * 1000回失敗するごとに
	 * 攻撃時間として60秒を仮想的に加算する。
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
						PASSWORD_MAX
								- PASSWORD_MIN
								+ 1);

		int attemptCount = 0;

		// 実際には待機していない仮想待機時間
		long virtualWaitTimeMillis = 0L;

		for (int i = PASSWORD_MIN;
				i <= PASSWORD_MAX;
				i++) {

			if (attemptCount
					>= actualMaxAttempts) {

				break;
			}

			String candidate =
					String.format(
							"%04d",
							i);

			attemptCount++;

			// -------------------------------------------------
			// 候補パスワードを1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					"総当たり攻撃 試行 "
							+ attemptCount
							+ " / "
							+ actualMaxAttempts
							+ " : "
							+ candidate);

			// -------------------------------------------------
			// パスワード一致確認
			// -------------------------------------------------

			if (passwordEncoder.matches(
					candidate,
					passwordHash)) {

				// 1000回目で成功した場合などは、
				// 仮想待機時間を追加しない。
				return new AttackResult(
						true,
						candidate,
						attemptCount,
						virtualWaitTimeMillis);
			}

			// -------------------------------------------------
			// 1000回失敗するごとに
			// 実際には待機せず60秒を仮想時間として加算
			// -------------------------------------------------

			if (attemptCount
					% WAIT_INTERVAL == 0) {

				virtualWaitTimeMillis +=
						WAIT_TIME_MILLIS;

				System.out.println(
						"総当たり攻撃 "
								+ attemptCount
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

		// -----------------------------------------------------
		// 攻撃失敗
		// -----------------------------------------------------

		return new AttackResult(
				false,
				null,
				attemptCount,
				virtualWaitTimeMillis);
	}

	public static class AttackResult {

		private final boolean success;

		private final String password;

		private final int attemptCount;

		/**
		 * 実際には待機していないが、
		 * 攻撃時間として加算する仮想待機時間
		 */
		private final long virtualWaitTimeMillis;

		public AttackResult(
				boolean success,
				String password,
				int attemptCount,
				long virtualWaitTimeMillis) {

			this.success = success;

			this.password = password;

			this.attemptCount = attemptCount;

			this.virtualWaitTimeMillis =
					virtualWaitTimeMillis;
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

		/**
		 * 実際には待機していないが、
		 * 攻撃時間として加算する仮想待機時間
		 */
		public long getVirtualWaitTimeMillis() {

			return virtualWaitTimeMillis;
		}
	}
}