
package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;

@Component
public class FactorAuthenticationAttack {

	private final MultiStagePasswordBruteForceAttack MultiStagepasswordBruteForceAttack;

	private final EmailOtpBruteForceAttack emailOtpBruteForceAttack;

	private final RandomPasswordAttack randomPasswordAttack;

	private final RandomEmailOtpAttack randomEmailOtpAttack;

	private final NewAuthLabLoginClient newAuthLabLoginClient;

	public FactorAuthenticationAttack(
			MultiStagePasswordBruteForceAttack MultiStagepasswordBruteForceAttack,
			EmailOtpBruteForceAttack emailOtpBruteForceAttack,
			RandomPasswordAttack randomPasswordAttack,
			RandomEmailOtpAttack randomEmailOtpAttack,
			NewAuthLabLoginClient newAuthLabLoginClient) {

		this.MultiStagepasswordBruteForceAttack = MultiStagepasswordBruteForceAttack;

		this.emailOtpBruteForceAttack = emailOtpBruteForceAttack;

		this.randomPasswordAttack = randomPasswordAttack;

		this.randomEmailOtpAttack = randomEmailOtpAttack;

		this.newAuthLabLoginClient = newAuthLabLoginClient;

	}

	// =========================================================
	// 一要素認証：Password総当たり
	// =========================================================

	public FactorAttackResult executeOneFactorPassword(
			String passwordHash,
			int maxAttemptsPassword) {

		int actualMaxAttempts = clampPasswordAttempts(
				maxAttemptsPassword);

		AttackResult result = MultiStagepasswordBruteForceAttack.executeOneStage(
				passwordHash,
				actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-password",
				"ID + Password",
				result.isSuccess(),
				result.getPassword(),
				null,
				result.getAttemptCount(),
				result.getVirtualWaitTimeMillis(),
				result.isForceTerminated(),
				null);
	}

	// =========================================================
	// 一要素認証：Passwordランダム攻撃
	// =========================================================

	public FactorAttackResult executeOneFactorRandomPassword(
			String passwordHash,
			int maxAttemptsPassword) {

		int actualMaxAttempts = clampPasswordAttempts(
				maxAttemptsPassword);

		RandomPasswordAttack.AttackResult result = randomPasswordAttack.execute(
				passwordHash,
				actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-password-random",
				"ID + Random Password",
				result.isSuccess(),
				result.getPassword(),
				null,
				result.getAttemptCount(),
				result.getVirtualWaitTimeMillis(),
				result.isForceTerminated(),
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

		int actualMaxAttempts = clampOtpAttempts(maxAttempts);

		EmailOtpBruteForceAttack.AttackResult result = emailOtpBruteForceAttack.execute(
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
				0,
				result.isTimeOut(),
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

		int actualMaxAttempts = clampOtpAttempts(maxAttempts);

		// =====================================================
		// OTPを送信する
		// =====================================================

		LoginResult sendResult = newAuthLabLoginClient.sendEmailOtp(
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
					0,
					false,
					sendResult);
		}

		// =====================================================
		// ランダムOTP攻撃
		// =====================================================

		RandomEmailOtpAttack.AttackResult result = randomEmailOtpAttack.execute(
				candidateOtp -> newAuthLabLoginClient.verifyEmailOtp(candidateOtp),
				actualMaxAttempts);

		return new FactorAttackResult(
				"one-factor-email-otp-random",
				"ID + Random Email OTP",
				result.isSuccess(),
				null,
				result.getOtp(),
				result.getAttemptCount(),
				0,
				result.isTimedOut(),
				result.getLoginResult());
	}

	// =========================================================
	// 二要素認証：Password → Email OTP総当たり
	// =========================================================

	public FactorAttackResult executeTwoFactorPasswordEmailOtp(
			String username,
			String passwordHash,
			int maxAttemptsPassword,
			int maxAttemptsOtp) {

		int actualMaxPasswordAttempts = clampPasswordAttempts(
				maxAttemptsPassword);

		int actualMaxOtpAttempts = clampOtpAttempts(
				maxAttemptsOtp);

		// =====================================================
		// 第1要素：Password総当たり
		// =====================================================

		AttackResult passResult = MultiStagepasswordBruteForceAttack.executeOneStage(
				passwordHash,
				actualMaxPasswordAttempts);

		// Password認証失敗
		if (!passResult.isSuccess()) {

			return new FactorAttackResult(
					"two-factor-password-email-otp",
					"ID + Password → Email OTP",
					false,
					null,
					null,
					passResult.getAttemptCount(),
					passResult.getVirtualWaitTimeMillis(),
					passResult.isForceTerminated(),
					null);
		}

		String foundPassword = passResult.getPassword();

		// =====================================================
		// 第2要素：Email OTP総当たり
		// =====================================================

		EmailOtpBruteForceAttack.AttackResult otpResult = emailOtpBruteForceAttack.executeTwoFactor(
				username,
				foundPassword,
				actualMaxOtpAttempts);

		// Password試行回数 + OTP試行回数
		int totalAttemptCount = passResult.getAttemptCount()
				+ otpResult.getAttemptCount();

		return new FactorAttackResult(
				"two-factor-password-email-otp",
				"ID + Password → Email OTP",
				otpResult.isSuccess(),
				foundPassword,
				otpResult.getOtp(),
				totalAttemptCount,
				passResult.getVirtualWaitTimeMillis(),
				passResult.isForceTerminated(),
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

		int actualMaxPasswordAttempts = clampPasswordAttempts(
				maxAttemptsPassword);

		int actualMaxOtpAttempts = clampOtpAttempts(
				maxAttemptsOtp);

		// =====================================================
		// 第1要素：Passwordランダム攻撃
		// =====================================================

		RandomPasswordAttack.AttackResult passResult = randomPasswordAttack.execute(
				passwordHash,
				actualMaxPasswordAttempts);

		// Password認証失敗
		if (!passResult.isSuccess()) {

			return new FactorAttackResult(
					"two-factor-password-email-otp-random",
					"ID + Random Password → Random Email OTP",
					false,
					null,
					null,
					passResult.getAttemptCount(),
					passResult.getVirtualWaitTimeMillis(),
					passResult.isForceTerminated(),
					null);
		}

		String foundPassword = passResult.getPassword();

		// =====================================================
		// 第2要素へ進む
		// 正しいPasswordでNewAuthLabにログイン
		// =====================================================

		LoginResult passwordLoginResult = newAuthLabLoginClient.loginTwoFactorPassword(
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
					passResult.getAttemptCount(),
					passResult.getVirtualWaitTimeMillis(),
					passResult.isForceTerminated(),
					passwordLoginResult);
		}

		System.out.println(
				"二要素認証Passwordログイン成功。");

		System.out.println(
				"NewAuthLabから二要素認証用OTPが発行されました。");

		// =====================================================
		// 第2要素：Email OTPランダム攻撃
		// =====================================================

		RandomEmailOtpAttack.AttackResult otpResult = randomEmailOtpAttack.execute(
				candidateOtp -> newAuthLabLoginClient.verifyTwoFactorOtp(candidateOtp),
				actualMaxOtpAttempts);

		// =====================================================
		// 総試行回数
		// =====================================================

		int totalAttemptCount = passResult.getAttemptCount()
				+ otpResult.getAttemptCount();

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
				passResult.getVirtualWaitTimeMillis(),
				passResult.isForceTerminated(),
				otpResult.getLoginResult());
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

	private int clampPasswordAttempts(int attempts) {

		return Math.max(
				1,
				Math.min(
						attempts,
						10_000));
	}

	private int clampOtpAttempts(int attempts) {

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

		private final long virtualWaitTimeMillis;

		private final LoginResult loginResult;

		private boolean forceTerminated = false;

		public FactorAttackResult(
				String authMethod,
				String authenticationConfiguration,
				boolean success,
				String password,
				String otp,
				int attemptCount,
				long virtualWaitTimeMillis,
				boolean forceTerminated,
				LoginResult loginResult) {

			this.authMethod = authMethod;

			this.authenticationConfiguration = authenticationConfiguration;

			this.success = success;

			this.password = password;

			this.otp = otp;

			this.attemptCount = attemptCount;

			this.virtualWaitTimeMillis = virtualWaitTimeMillis;

			this.forceTerminated = forceTerminated;

			this.loginResult = loginResult;

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

		public long getVirtualWaitTimeMillis() {
			return virtualWaitTimeMillis;
		}

		public boolean isForceTerminated() {
			return forceTerminated;
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

		/// =========================================================
		/// 試行制限による強制終了かどうか なぎ

		public void setForceTerminated(boolean forceTerminated) {
			this.forceTerminated = forceTerminated;

		}
		///=========================================================
	}
}
