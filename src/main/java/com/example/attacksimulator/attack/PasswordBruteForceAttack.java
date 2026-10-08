package com.example.attacksimulator.attack;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordBruteForceAttack {

	private static final int PASSWORD_MIN = 0;

	private static final int PASSWORD_MAX = 9999;

	/**
	 * 試行制限のしきい値
	 *
	 * 1000回失敗するごとに試行制限が発生する。
	 */
	private static final int WAIT_INTERVAL =
			1_000;

	/**
	 * 試行制限による仮想待機時間
	 *
	 * 実際には待機しない。
	 *
	 * 1回目：60秒
	 * 2回目：5分
	 * 3回目：10分
	 * 4回目：20分
	 *
	 * 5回目：攻撃処理を強制終了
	 *
	 * ※5回目の強制終了時には
	 * 追加の仮想待機時間は加算しない。
	 */
	private static final long[] WAIT_TIMES = {

			60_000L,       // 1回目：1分

			300_000L,      // 2回目：5分

			600_000L,      // 3回目：10分

			1_200_000L     // 4回目：20分
	};

	/**
	 * 5回目の試行制限で
	 * 攻撃処理を強制終了する。
	 *
	 * 5000回失敗した時点で強制終了。
	 *
	 * 実際のアカウントロックは行わない。
	 */
	private static final int FORCE_TERMINATION_RESTRICTION_COUNT =
			5;

	private final PasswordEncoder passwordEncoder;

	public PasswordBruteForceAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder =
				passwordEncoder;
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
	 * 1000回失敗するごとに試行制限を発生させる。
	 *
	 * 1回目：1分
	 * 2回目：5分
	 * 3回目：10分
	 * 4回目：20分
	 * 5回目：攻撃処理を強制終了
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

				// 正解した場合は、
				// その試行が1000回目・2000回目・
				// 3000回目・4000回目・5000回目
				// であっても、試行制限による
				// 仮想時間は追加しない。

				return new AttackResult(
						true,
						candidate,
						attemptCount,
						virtualWaitTimeMillis,
						false);
			}

			// -------------------------------------------------
			// 1000回失敗するごとに試行制限
			// -------------------------------------------------

			if (attemptCount
					% WAIT_INTERVAL == 0) {

				int restrictionCount =
						attemptCount
								/ WAIT_INTERVAL;

				// -------------------------------------------------
				// 5回目
				// 攻撃処理を強制終了
				//
				// 5000回失敗した時点で終了。
				//
				// 実際のアカウントロックは行わない。
				// -------------------------------------------------

				if (restrictionCount
						>= FORCE_TERMINATION_RESTRICTION_COUNT) {

					System.out.println(
							"========================================");

					System.out.println(
							"総当たり攻撃 "
									+ attemptCount
									+ "回失敗");

					System.out.println(
							"試行制限 "
									+ restrictionCount
									+ "回目");

					System.out.println(
							"攻撃処理を強制終了します。");

					System.out.println(
							"※実際のアカウントロックは行いません。");

					System.out.println(
							"累積仮想待機時間 = "
									+ virtualWaitTimeMillis
									+ " ms");

					System.out.println(
							"========================================");

					return new AttackResult(
							false,
							null,
							attemptCount,
							virtualWaitTimeMillis,
							true);
				}

				// -------------------------------------------------
				// 1～4回目の試行制限
				// -------------------------------------------------

				long waitTimeMillis =
						WAIT_TIMES[
								restrictionCount - 1];

				virtualWaitTimeMillis +=
						waitTimeMillis;

				System.out.println(
						"========================================");

				System.out.println(
						"総当たり攻撃 "
								+ attemptCount
								+ "回失敗");

				System.out.println(
						"試行制限 "
								+ restrictionCount
								+ "回目");

				System.out.println(
						"仮想待機時間 "
								+ waitTimeMillis
								+ " ms を加算");

				System.out.println(
						"累積仮想待機時間 = "
								+ virtualWaitTimeMillis
								+ " ms");

				System.out.println(
						"※実際には待機していません。");

				System.out.println(
						"========================================");
			}
		}

		// -----------------------------------------------------
		// 攻撃失敗
		// -----------------------------------------------------

		return new AttackResult(
				false,
				null,
				attemptCount,
				virtualWaitTimeMillis,
				false);
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

		/**
		 * 試行制限によって
		 * 攻撃処理が強制終了されたかどうか
		 *
		 * 実際のアカウントロックではない。
		 */
		private final boolean forceTerminated;

		public AttackResult(
				boolean success,
				String password,
				int attemptCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated) {

			this.success = success;

			this.password = password;

			this.attemptCount = attemptCount;

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

		/**
		 * 試行制限によって
		 * 攻撃処理が強制終了されたかどうか
		 *
		 * 実際のアカウントロックではない。
		 */
		public boolean isForceTerminated() {
			return forceTerminated;
		}
	}
}