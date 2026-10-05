package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;

@Component
public class FactorAuthenticationAttack {

	private final PasswordBruteForceAttack passwordBruteForceAttack;

	private final EmailOtpBruteForceAttack emailOtpBruteForceAttack;

	private final RandomPasswordAttack randomPasswordAttack;

	private final RandomEmailOtpAttack randomEmailOtpAttack;

	private final NewAuthLabLoginClient newAuthLabLoginClient;

	public FactorAuthenticationAttack(
			PasswordBruteForceAttack passwordBruteForceAttack,
			EmailOtpBruteForceAttack emailOtpBruteForceAttack,
			RandomPasswordAttack randomPasswordAttack,
			RandomEmailOtpAttack randomEmailOtpAttack,
			NewAuthLabLoginClient newAuthLabLoginClient) {

		this.passwordBruteForceAttack =
				passwordBruteForceAttack;

		this.emailOtpBruteForceAttack =
				emailOtpBruteForceAttack;

		this.randomPasswordAttack =
				randomPasswordAttack;

		this.randomEmailOtpAttack =
				randomEmailOtpAttack;

		this.newAuthLabLoginClient =
				newAuthLabLoginClient;
	}

	// =========================================================
	// 一要素認証：Password総当たり
	// =========================================================

	public FactorAttackResult executeOneFactorPassword(
			String passwordHash,
			int maxAttemptsPassword) {

		int actualMaxAttempts =
				clampPasswordAttempts(
						maxAttemptsPassword);

		PasswordBruteForceAttack.AttackResult result =
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
	// 一要素認証：Passwordランダム攻撃
	// =========================================================

	public FactorAttackResult executeOneFactorRandomPassword(
			String passwordHash) {

		return executeOneFactorRandomPassword(
				passwordHash,
				10_000);
	}

	public FactorAttackResult executeOneFactorRandomPassword(
			String passwordHash,
			int maxAttemptsPassword) {

		int actualMaxAttempts =
				clampPasswordAttempts(
						maxAttemptsPassword);

		RandomPasswordAttack.AttackResult result =
				randomPasswordAttack.execute(
						passwordHash,
						actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-password-random",
				"ID + Random Password",
				result.isSuccess(),
				result.getPassword(),
				null,
				result.getAttemptCount(),
				null);
	}

	// =========================================================
	// 一要素認証：Email OTP総当たり
	// =========================================================

	public FactorAttackResult executeOneFactorEmailOtp(
			String username,
			String email,
			int maxAttempts) {

		validateUsernameAndEmail(
				username,
				email);

		int actualMaxAttempts =
				clampOtpAttempts(maxAttempts);

		EmailOtpBruteForceAttack.AttackResult result =
				emailOtpBruteForceAttack.execute(
						username,
						email,
						actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-email-otp",
				"ID + Email OTP",
				result.isSuccess(),
				null,
				result.getOtp(),
				result.getAttemptCount(),
				result.getLoginResult());
	}

	// =========================================================
	// 一要素認証：Email OTPランダム攻撃
	// =========================================================

	public FactorAttackResult executeOneFactorRandomEmailOtp(
			String username,
			String email) {

		return executeOneFactorRandomEmailOtp(
				username,
				email,
				1_000_000);
	}

	public FactorAttackResult executeOneFactorRandomEmailOtp(
			String username,
			String email,
			int maxAttempts) {

		validateUsernameAndEmail(
				username,
				email);

		int actualMaxAttempts =
				clampOtpAttempts(maxAttempts);

		// =====================================================
		// OTPを送信する
		// =====================================================

		LoginResult sendResult =
				newAuthLabLoginClient.sendEmailOtp(
						username,
						email);

		if (sendResult == null
				|| !sendResult.isRequestSuccess()) {

			return new FactorAttackResult(
					"one-factor-email-otp-random",
					"ID + Random Email OTP",
					false,
					null,
					null,
					0,
					sendResult);
		}

		// =====================================================
		// ランダムOTP攻撃
		// =====================================================

		final LoginResult[] successfulLogin =
				new LoginResult[1];

		RandomEmailOtpAttack.AttackResult result =
				randomEmailOtpAttack.execute(
						candidateOtp -> {

							LoginResult verifyResult =
									newAuthLabLoginClient
											.verifyEmailOtp(
													candidateOtp);

							if (verifyResult != null
									&& verifyResult.isSuccess()) {

								successfulLogin[0] =
										verifyResult;

								return true;
							}

							return false;
						},
						actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-email-otp-random",
				"ID + Random Email OTP",
				result.isSuccess(),
				null,
				result.getOtp(),
				result.getAttemptCount(),
				successfulLogin[0]);
	}

	// =========================================================
	// 二要素認証：Password → Email OTP総当たり
	// =========================================================

	public FactorAttackResult executeTwoFactorPasswordEmailOtp(
			String username,
			String passwordHash,
			int maxAttemptsPassword,
			int maxAttemptsOtp) {

		int actualMaxPasswordAttempts =
				clampPasswordAttempts(
						maxAttemptsPassword);

		int actualMaxOtpAttempts =
				clampOtpAttempts(
						maxAttemptsOtp);

		// =====================================================
		// 第1要素：Password総当たり
		// =====================================================

		PasswordBruteForceAttack.AttackResult passwordResult =
				passwordBruteForceAttack.execute(
						passwordHash,
						actualMaxPasswordAttempts);

		if (!passwordResult.isSuccess()) {

			return new FactorAttackResult(
					"two-factor-password-email-otp",
					"ID + Password → Email OTP",
					false,
					null,
					null,
					passwordResult.getAttemptCount(),
					null);
		}

		String foundPassword =
				passwordResult.getPassword();

		// =====================================================
		// 第2要素：Email OTP総当たり
		// =====================================================

		EmailOtpBruteForceAttack.AttackResult otpResult =
				emailOtpBruteForceAttack.executeTwoFactor(
						username,
						foundPassword,
						actualMaxOtpAttempts);

		int totalAttemptCount =
				passwordResult.getAttemptCount()
						+ otpResult.getAttemptCount();

		return new FactorAttackResult(
				"two-factor-password-email-otp",
				"ID + Password → Email OTP",
				otpResult.isSuccess(),
				foundPassword,
				otpResult.getOtp(),
				totalAttemptCount,
				otpResult.getLoginResult());
	}

	// =========================================================
	// 二要素認証：Random Password → Random Email OTP
	// =========================================================

	public FactorAttackResult executeTwoFactorRandomPasswordEmailOtp(
			String username,
			String passwordHash,
			int maxAttemptsPassword,
			int maxAttemptsOtp) {

		int actualMaxPasswordAttempts =
				clampPasswordAttempts(
						maxAttemptsPassword);

		int actualMaxOtpAttempts =
				clampOtpAttempts(
						maxAttemptsOtp);

		// =====================================================
		// 第1要素：Passwordランダム攻撃
		// =====================================================

		RandomPasswordAttack.AttackResult passwordResult =
				randomPasswordAttack.execute(
						passwordHash,
						actualMaxPasswordAttempts);

		if (!passwordResult.isSuccess()) {

			return new FactorAttackResult(
					"two-factor-password-email-otp-random",
					"ID + Random Password → Random Email OTP",
					false,
					null,
					null,
					passwordResult.getAttemptCount(),
					null);
		}

		String foundPassword =
				passwordResult.getPassword();

		// =====================================================
		// 第2要素へ進む
		// 正しいPasswordでNewAuthLabにログイン
		// =====================================================

		LoginResult passwordLoginResult =
				newAuthLabLoginClient
						.loginTwoFactorPassword(
								username,
								foundPassword);

		if (passwordLoginResult == null
				|| !passwordLoginResult.isRequestSuccess()) {

			System.out.println(
					"二要素認証のPasswordログインに失敗しました。");

			return new FactorAttackResult(
					"two-factor-password-email-otp-random",
					"ID + Random Password → Random Email OTP",
					false,
					foundPassword,
					null,
					passwordResult.getAttemptCount(),
					passwordLoginResult);
		}

		System.out.println(
				"二要素認証Passwordログイン成功。");

		System.out.println(
				"NewAuthLabから二要素認証用OTPが発行されました。");

		// =====================================================
		// 第2要素：Email OTPランダム攻撃
		// =====================================================

		final LoginResult[] successfulLogin =
				new LoginResult[1];

		RandomEmailOtpAttack.AttackResult otpResult =
				randomEmailOtpAttack.execute(
						candidateOtp -> {

							LoginResult verifyResult =
									newAuthLabLoginClient
											.verifyTwoFactorOtp(
													candidateOtp);

							if (verifyResult != null
									&& verifyResult.isSuccess()) {

								successfulLogin[0] =
										verifyResult;

								return true;
							}

							return false;
						},
						actualMaxOtpAttempts);

		// =====================================================
		// 総試行回数
		// =====================================================

		int totalAttemptCount =
				passwordResult.getAttemptCount()
						+ otpResult.getAttemptCount();

		System.out.println(
				"Password試行回数 = "
						+ passwordResult.getAttemptCount());

		System.out.println(
				"OTP試行回数 = "
						+ otpResult.getAttemptCount());

		System.out.println(
				"総試行回数 = "
						+ totalAttemptCount);

		// =====================================================
		// 結果
		// =====================================================

		return new FactorAttackResult(
				"two-factor-password-email-otp-random",
				"ID + Random Password → Random Email OTP",
				otpResult.isSuccess(),
				foundPassword,
				otpResult.getOtp(),
				totalAttemptCount,
				successfulLogin[0]);
	}

	// =========================================================
	// 入力値チェック
	// =========================================================

	private void validateUsernameAndEmail(
			String username,
			String email) {

		if (username == null
				|| username.isBlank()) {

			throw new IllegalArgumentException(
					"ユーザー名を指定してください。");
		}

		if (email == null
				|| email.isBlank()) {

			throw new IllegalArgumentException(
					"メールアドレスを指定してください。");
		}
	}

	// =========================================================
	// 試行回数の上限
	// =========================================================

	private int clampPasswordAttempts(
			int attempts) {

		return Math.max(
				1,
				Math.min(
						attempts,
						10_000));
	}

	private int clampOtpAttempts(
			int attempts) {

		return Math.max(
				1,
				Math.min(
						attempts,
						1_000_000));
	}

	// =========================================================
	// 認証攻撃の結果
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

		public boolean isLoginSuccess() {

			return loginResult != null
					&& loginResult.isSuccess();
		}

		public String getFinalUrl() {

			if (loginResult == null) {
				return null;
			}

			return loginResult.getFinalUrl();
		}

		public String getSessionCookie() {

			if (loginResult == null) {
				return null;
			}

			return loginResult.getSessionCookie();
		}
	}
}