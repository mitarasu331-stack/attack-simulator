package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;

@Component
public class FactorAuthenticationAttack {

	private final PasswordBruteForceAttack
	passwordBruteForceAttack;

	private final EmailOtpBruteForceAttack
	emailOtpBruteForceAttack;

	private final NewAuthLabLoginClient
	newAuthLabLoginClient;

	private final RandomPasswordAttack
	randomPasswordAttack;

	public FactorAuthenticationAttack(
			PasswordBruteForceAttack passwordBruteForceAttack,
			EmailOtpBruteForceAttack emailOtpBruteForceAttack,
			NewAuthLabLoginClient newAuthLabLoginClient,
			RandomPasswordAttack randomPasswordAttack) {

		this.passwordBruteForceAttack =
				passwordBruteForceAttack;

		this.emailOtpBruteForceAttack =
				emailOtpBruteForceAttack;

		this.newAuthLabLoginClient =
				newAuthLabLoginClient;

		this.randomPasswordAttack =
				randomPasswordAttack;
	}

	// =========================================================
	// 一要素認証
	// ID + Password
	// 通常のPassword総当たり
	// =========================================================

	/**
	 * 既存互換用
	 *
	 * 最大10000回
	 */
	public FactorAttackResult
	executeOneFactorPassword(
			String passwordHash) {

		return executeOneFactorPassword(
				passwordHash,
				10_000);
	}

	/**
	 * Password最大試行回数を指定
	 */
	public FactorAttackResult
	executeOneFactorPassword(
			String passwordHash,
			int maxAttemptsPassword) {

		int actualMaxAttempts =
				clampPasswordAttempts(
						maxAttemptsPassword);

		PasswordBruteForceAttack.AttackResult
		result =
		passwordBruteForceAttack.execute(
				passwordHash,
				actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-password",
				"ID + Password",
				result.isSuccess(),
				result.getPassword(),
				null,
				result.getAttemptCount(),
				null);
	}

	// =========================================================
	// 一要素認証
	// ID + Random Password
	// ランダム順のPassword総当たり
	// =========================================================

	/**
	 * 既存互換用
	 *
	 * 最大10000回
	 */
	public FactorAttackResult
	executeOneFactorRandomPassword(
			String passwordHash) {

		return executeOneFactorRandomPassword(
				passwordHash,
				10_000);
	}

	/**
	 * Random Password最大試行回数を指定
	 */
	public FactorAttackResult
	executeOneFactorRandomPassword(
			String passwordHash,
			int maxAttemptsPassword) {

		int actualMaxAttempts =
				clampPasswordAttempts(
						maxAttemptsPassword);

		RandomPasswordAttack.AttackResult
		result =
		randomPasswordAttack.execute(
				passwordHash,
				actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-random-password",
				"ID + Random Password",
				result.isSuccess(),
				result.getPassword(),
				null,
				result.getAttemptCount(),
				null);
	}

	// =========================================================
	// 一要素認証
	// Email OTP
	// =========================================================

	/**
	 * Email OTPのみ
	 *
	 * usernameで対象ユーザーを特定し、
	 * emailはOTPの送信先として使用する。
	 *
	 * メールアドレスが重複していても、
	 * usernameが異なれば別ユーザーとして扱う。
	 */
	public FactorAttackResult
	executeOneFactorEmailOtp(
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

		int actualMaxAttempts =
				clampOtpAttempts(
						maxAttempts);

		EmailOtpBruteForceAttack.AttackResult
		result =
		emailOtpBruteForceAttack.execute(
				username,
				email,
				actualMaxAttempts);

		LoginResult loginResult =
				result.getLoginResult();

		return new FactorAttackResult(
				"one-factor-email-otp",
				"ID + Email OTP",
				result.isSuccess(),
				null,
				result.getOtp(),
				result.getAttemptCount(),
				loginResult);
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// =========================================================

	/**
	 * 既存互換用。
	 *
	 * Password       最大10000回
	 * Email OTP      最大1000000回
	 */
	public FactorAttackResult
	executeTwoFactorPasswordEmailOtp(
			String username,
			String passwordHash) {

		return executeTwoFactorPasswordEmailOtp(
				username,
				passwordHash,
				10_000,
				1_000_000);
	}

	/**
	 * PasswordとEmail OTPの最大試行回数を
	 * 個別に指定して実行する。
	 */
	public FactorAttackResult
	executeTwoFactorPasswordEmailOtp(
			String username,
			String passwordHash,
			int maxAttemptsPassword,
			int maxAttemptsOtp) {

		// =====================================================
		// 入力チェック
		// =====================================================

		if (username == null
				|| username.isBlank()) {

			throw new IllegalArgumentException(
					"ユーザー名が指定されていません。");
		}

		if (passwordHash == null
				|| passwordHash.isBlank()) {

			throw new IllegalArgumentException(
					"パスワードハッシュが指定されていません。");
		}

		// =====================================================
		// 最大試行回数
		// =====================================================

		int actualMaxAttemptsPassword =
				clampPasswordAttempts(
						maxAttemptsPassword);

		int actualMaxAttemptsOtp =
				clampOtpAttempts(
						maxAttemptsOtp);

		// =====================================================
		// Password総当たり
		// =====================================================

		PasswordBruteForceAttack.AttackResult
		passwordResult =
		passwordBruteForceAttack.execute(
				passwordHash,
				actualMaxAttemptsPassword);

		int passwordAttemptCount =
				passwordResult.getAttemptCount();

		// =====================================================
		// Password失敗
		// =====================================================

		if (!passwordResult.isSuccess()) {

			return new FactorAttackResult(
					"two-factor-password-email-otp",
					"ID + Password → Email OTP",
					false,
					null,
					null,
					passwordAttemptCount,
					null);
		}

		// =====================================================
		// Password成功
		// =====================================================

		String password =
				passwordResult.getPassword();

		System.out.println(
				"========================================");

		System.out.println(
				"二要素認証 Password突破成功");

		System.out.println(
				"username = "
						+ username);

		System.out.println(
				"password = "
						+ password);

		System.out.println(
				"Password試行回数 = "
						+ passwordAttemptCount);

		System.out.println(
				"OTP最大試行回数 = "
						+ actualMaxAttemptsOtp);

		System.out.println(
				"========================================");

		// =====================================================
		// Password成功後
		//
		// ↓
		// EmailOtpBruteForceAttack
		// ↓
		// newauthlabでOTP発行
		// ↓
		// OTP総当たり
		// =====================================================

		EmailOtpBruteForceAttack.AttackResult
		otpResult =
		emailOtpBruteForceAttack
		.executeTwoFactor(
				username,
				password,
				actualMaxAttemptsOtp);

		// =====================================================
		// OTP試行回数
		// =====================================================

		int otpAttemptCount =
				otpResult.getAttemptCount();

		// =====================================================
		// OTP取得
		// =====================================================

		String otp =
				otpResult.getOtp();

		// =====================================================
		// 最終成功判定
		// =====================================================

		boolean success =
				otpResult.isSuccess();

		// =====================================================
		// ログイン結果
		// =====================================================

		LoginResult loginResult =
				otpResult.getLoginResult();

		// =====================================================
		// 結果表示
		// =====================================================

		System.out.println(
				"========================================");

		System.out.println(
				"二要素認証結果");

		System.out.println(
				"username = "
						+ username);

		System.out.println(
				"Password = "
						+ password);

		System.out.println(
				"Password試行回数 = "
						+ passwordAttemptCount);

		System.out.println(
				"OTP = "
						+ otp);

		System.out.println(
				"OTP試行回数 = "
						+ otpAttemptCount);

		System.out.println(
				"実ログイン成功 = "
						+ success);

		if (loginResult != null) {

			System.out.println(
					"Final URL = "
							+ loginResult.getFinalUrl());
		}

		System.out.println(
				"========================================");

		// =====================================================
		// 二要素認証の総当たり結果
		// =====================================================

		return new FactorAttackResult(
				"two-factor-password-email-otp",
				"ID + Password → Email OTP",
				success,
				password,
				otp,
				passwordAttemptCount
						+ otpAttemptCount,
				loginResult);
	}

	// =========================================================
	// Password試行回数制限
	// =========================================================

	private int clampPasswordAttempts(
			int maxAttempts) {

		if (maxAttempts < 1) {
			return 1;
		}

		if (maxAttempts > 10_000) {
			return 10_000;
		}

		return maxAttempts;
	}

	// =========================================================
	// Email OTP試行回数制限
	// =========================================================

	private int clampOtpAttempts(
			int maxAttempts) {

		if (maxAttempts < 1) {
			return 1;
		}

		if (maxAttempts > 1_000_000) {
			return 1_000_000;
		}

		return maxAttempts;
	}

	// =========================================================
	// 結果クラス
	// =========================================================

	public static class FactorAttackResult {

		private final String authMethod;

		private final String authenticationConfiguration;

		private final boolean success;

		private final String password;

		private final String otp;

		private final int attemptCount;

		private final LoginResult loginResult;

		public FactorAttackResult(
				String authMethod,
				String authenticationConfiguration,
				boolean success,
				String password,
				String otp,
				int attemptCount,
				LoginResult loginResult) {

			this.authMethod =
					authMethod;

			this.authenticationConfiguration =
					authenticationConfiguration;

			this.success =
					success;

			this.password =
					password;

			this.otp =
					otp;

			this.attemptCount =
					attemptCount;

			this.loginResult =
					loginResult;
		}

		// =====================================================
		// Getter
		// =====================================================

		public String getAuthMethod() {
			return authMethod;
		}

		public String getAuthenticationConfiguration() {
			return authenticationConfiguration;
		}

		public boolean isSuccess() {
			return success;
		}

		public String getPassword() {
			return password;
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

		// =====================================================
		// 実ログイン成功
		// =====================================================

		public boolean isLoginSuccess() {

			return loginResult != null
					&& loginResult.isSuccess();
		}

		// =====================================================
		// Final URL
		// =====================================================

		public String getFinalUrl() {

			if (loginResult == null) {
				return null;
			}

			return loginResult.getFinalUrl();
		}

		// =====================================================
		// Session Cookie
		// =====================================================

		public String getSessionCookie() {

			if (loginResult == null) {
				return null;
			}

			return loginResult.getSessionCookie();
		}
	}
}