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

	public FactorAuthenticationAttack(
			PasswordBruteForceAttack passwordBruteForceAttack,
			EmailOtpBruteForceAttack emailOtpBruteForceAttack,
			NewAuthLabLoginClient newAuthLabLoginClient) {

		this.passwordBruteForceAttack =
				passwordBruteForceAttack;

		this.emailOtpBruteForceAttack =
				emailOtpBruteForceAttack;

		this.newAuthLabLoginClient =
				newAuthLabLoginClient;
	}

	// =========================================================
	// 一要素認証
	// Password
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
				3,
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
	 */
	public FactorAttackResult
	executeOneFactorEmailOtp(
			String email,
			int maxAttempts) {

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
				email,
				actualMaxAttempts);

		LoginResult loginResult =
				result.getLoginResult();

		return new FactorAttackResult(
				"one-factor-email-otp",
				"ID + Email OTP",
				3,
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
					5,
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
		// ↓
		// newauthlabでOTP発行
		// ↓
		// OTP総当たり
		// =====================================================

		LoginResult loginResult =
				newAuthLabLoginClient
				.loginTwoFactorPasswordEmailOtp(
						username,
						password,
						actualMaxAttemptsOtp);

		// =====================================================
		// OTP試行回数
		// =====================================================

		int otpAttemptCount =
				loginResult.getAttemptCount();

		// =====================================================
		// 実際の総攻撃試行回数
		//
		// Password試行回数
		// +
		// OTP試行回数
		// =====================================================

		int totalAttempts =
				passwordAttemptCount
				+ otpAttemptCount;

		// =====================================================
		// OTP取得
		// =====================================================

		String otp =
				loginResult.getOtp();

		// =====================================================
		// 最終成功判定
		//
		// OTPまで成功し、
		// ticket発行まで成功した場合
		// =====================================================

		boolean success =
				loginResult.isSuccess();

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
				"総攻撃試行回数 = "
						+ totalAttempts);

		System.out.println(
				"実ログイン成功 = "
						+ success);

		System.out.println(
				"Final URL = "
						+ loginResult.getFinalUrl());

		System.out.println(
				"========================================");

		// =====================================================
		// 二要素認証の総当たり結果
		// =====================================================

		return new FactorAttackResult(
				"two-factor-password-email-otp",
				"ID + Password → Email OTP",
				5,
				success,
				password,
				otp,
				totalAttempts,
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

		private final int operationCount;

		private final boolean success;

		private final String password;

		private final String otp;

		private final int attemptCount;

		private final LoginResult loginResult;

		public FactorAttackResult(
				String authMethod,
				String authenticationConfiguration,
				int operationCount,
				boolean success,
				String password,
				String otp,
				int attemptCount,
				LoginResult loginResult) {

			this.authMethod =
					authMethod;

			this.authenticationConfiguration =
					authenticationConfiguration;

			this.operationCount =
					operationCount;

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
		// 旧形式互換コンストラクタ
		// =====================================================

		public FactorAttackResult(
				String authMethod,
				String authenticationConfiguration,
				int operationCount,
				boolean success,
				String password,
				String otp,
				int attemptCount) {

			this(
					authMethod,
					authenticationConfiguration,
					operationCount,
					success,
					password,
					otp,
					attemptCount,
					null);
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

		public int getOperationCount() {
			return operationCount;
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