package com.example.attacksimulator.service;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.PasswordBruteForceAttack;
import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;
import com.example.attacksimulator.model.NewAuthLabUser;
import com.example.attacksimulator.repository.NewAuthLabUserRepository;

@Service
public class AttackService {

	private final PasswordBruteForceAttack
	passwordBruteForceAttack;

	private final MultiStagePasswordBruteForceAttack
	multiStagePasswordBruteForceAttack;

	private final EmailOtpBruteForceAttack
	emailOtpBruteForceAttack;

	private final FactorAuthenticationAttack
	factorAuthenticationAttack;

	private final NewAuthLabUserRepository
	newAuthLabUserRepository;

	private final NewAuthLabLoginClient
	newAuthLabLoginClient;

	public AttackService(
			PasswordBruteForceAttack passwordBruteForceAttack,
			MultiStagePasswordBruteForceAttack
			multiStagePasswordBruteForceAttack,
			EmailOtpBruteForceAttack
			emailOtpBruteForceAttack,
			FactorAuthenticationAttack
			factorAuthenticationAttack,
			NewAuthLabUserRepository
			newAuthLabUserRepository,
			NewAuthLabLoginClient
			newAuthLabLoginClient) {

		this.passwordBruteForceAttack =
				passwordBruteForceAttack;

		this.multiStagePasswordBruteForceAttack =
				multiStagePasswordBruteForceAttack;

		this.emailOtpBruteForceAttack =
				emailOtpBruteForceAttack;

		this.factorAuthenticationAttack =
				factorAuthenticationAttack;

		this.newAuthLabUserRepository =
				newAuthLabUserRepository;

		this.newAuthLabLoginClient =
				newAuthLabLoginClient;
	}

	// =========================================================
	// ユーザー取得
	// =========================================================

	public NewAuthLabUser getUser(
			String username) {

		return newAuthLabUserRepository
				.findByUsername(username)
				.orElseThrow(() ->
				new IllegalArgumentException(
						"指定されたユーザーが見つかりません: "
								+ username));
	}

	// =========================================================
	// 一段階認証
	// Password
	// =========================================================

	/**
	 * 既存互換版
	 *
	 * Password最大10000回
	 */
	public MultiStagePasswordBruteForceAttack.AttackResult
	executeOneStage(
			String username) {

		return executeOneStage(
				username,
				10_000);
	}

	/**
	 * Passwordの最大試行回数を指定
	 */
	public MultiStagePasswordBruteForceAttack.AttackResult
	executeOneStage(
			String username,
			int maxAttemptsPassword) {

		NewAuthLabUser user =
				getUser(username);

		return multiStagePasswordBruteForceAttack
				.executeOneStage(
						user.getPassword(),
						maxAttemptsPassword);
	}

	// =========================================================
	// 一段階認証
	// 実ログイン付き
	// =========================================================

	public OneStageLoginResult
	executeOneStageWithLogin(
			String username) {

		return executeOneStageWithLogin(
				username,
				10_000);
	}

	public OneStageLoginResult
	executeOneStageWithLogin(
			String username,
			int maxAttemptsPassword) {

		MultiStagePasswordBruteForceAttack.AttackResult
		attackResult =
		executeOneStage(
				username,
				maxAttemptsPassword);

		// -----------------------------------------------------
		// Password総当たり失敗
		// -----------------------------------------------------

		if (!attackResult.isSuccess()) {

			return new OneStageLoginResult(
					attackResult,
					false,
					null);
		}

		// -----------------------------------------------------
		// newauthlabへ実ログイン
		// -----------------------------------------------------

		LoginResult loginResult =
				newAuthLabLoginClient.loginOneStage(
						username,
						attackResult.getPassword());

		return new OneStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// 二段階認証
	// Password → Password2
	// =========================================================

	/**
	 * 既存互換版
	 *
	 * Password  最大10000回
	 * Password2 最大10000回
	 */
	public MultiStagePasswordBruteForceAttack.AttackResult
	executeTwoStage(
			String username) {

		return executeTwoStage(
				username,
				10_000,
				10_000);
	}

	/**
	 * Password / Password2の最大試行回数を個別指定
	 */
	public MultiStagePasswordBruteForceAttack.AttackResult
	executeTwoStage(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2) {

		NewAuthLabUser user =
				getUser(username);

		return multiStagePasswordBruteForceAttack
				.executeTwoStage(
						user.getPassword(),
						user.getPassword2(),
						maxAttemptsPassword,
						maxAttemptsPassword2);
	}

	// =========================================================
	// 二段階認証
	// 実ログイン付き
	// =========================================================

	public TwoStageLoginResult
	executeTwoStageWithLogin(
			String username) {

		return executeTwoStageWithLogin(
				username,
				10_000,
				10_000);
	}

	public TwoStageLoginResult
	executeTwoStageWithLogin(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2) {

		MultiStagePasswordBruteForceAttack.AttackResult
		attackResult =
		executeTwoStage(
				username,
				maxAttemptsPassword,
				maxAttemptsPassword2);

		// -----------------------------------------------------
		// 総当たり失敗
		// -----------------------------------------------------

		if (!attackResult.isSuccess()) {

			return new TwoStageLoginResult(
					attackResult,
					false,
					null);
		}

		// -----------------------------------------------------
		// newauthlabへ実ログイン
		// -----------------------------------------------------

		LoginResult loginResult =
				newAuthLabLoginClient.loginTwoStage(
						username,
						attackResult.getPassword(),
						attackResult.getPassword2());

		return new TwoStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// 三段階認証
	// Password → Password2 → Password3
	// =========================================================

	/**
	 * 既存互換版
	 */
	public MultiStagePasswordBruteForceAttack.AttackResult
	executeThreeStage(
			String username) {

		return executeThreeStage(
				username,
				10_000,
				10_000,
				10_000);
	}

	/**
	 * Password / Password2 / Password3を個別指定
	 */
	public MultiStagePasswordBruteForceAttack.AttackResult
	executeThreeStage(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2,
			int maxAttemptsPassword3) {

		NewAuthLabUser user =
				getUser(username);

		return multiStagePasswordBruteForceAttack
				.executeThreeStage(
						user.getPassword(),
						user.getPassword2(),
						user.getPassword3(),
						maxAttemptsPassword,
						maxAttemptsPassword2,
						maxAttemptsPassword3);
	}

	// =========================================================
	// 三段階認証
	// 実ログイン付き
	// =========================================================

	public ThreeStageLoginResult
	executeThreeStageWithLogin(
			String username) {

		return executeThreeStageWithLogin(
				username,
				10_000,
				10_000,
				10_000);
	}

	public ThreeStageLoginResult
	executeThreeStageWithLogin(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2,
			int maxAttemptsPassword3) {

		MultiStagePasswordBruteForceAttack.AttackResult
		attackResult =
		executeThreeStage(
				username,
				maxAttemptsPassword,
				maxAttemptsPassword2,
				maxAttemptsPassword3);

		// -----------------------------------------------------
		// 総当たり失敗
		// -----------------------------------------------------

		if (!attackResult.isSuccess()) {

			return new ThreeStageLoginResult(
					attackResult,
					false,
					null);
		}

		// -----------------------------------------------------
		// newauthlabへ実ログイン
		// -----------------------------------------------------

		LoginResult loginResult =
				newAuthLabLoginClient.loginThreeStage(
						username,
						attackResult.getPassword(),
						attackResult.getPassword2(),
						attackResult.getPassword3());

		return new ThreeStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// Password総当たり
	// =========================================================

	/**
	 * 既存互換版
	 */
	public PasswordBruteForceAttack.AttackResult
	executePasswordBruteForce(
			String username) {

		return executePasswordBruteForce(
				username,
				10_000);
	}

	/**
	 * Password最大試行回数を指定
	 */
	public PasswordBruteForceAttack.AttackResult
	executePasswordBruteForce(
			String username,
			int maxAttempts) {

		NewAuthLabUser user =
				getUser(username);

		return passwordBruteForceAttack
				.execute(
						user.getPassword(),
						maxAttempts);
	}

	// =========================================================
	// 一要素認証
	// Password
	// =========================================================

	/**
	 * 既存互換版
	 */
	public FactorAuthenticationAttack.FactorAttackResult
	executeOneFactorPassword(
			String username) {

		return executeOneFactorPassword(
				username,
				10_000);
	}

	/**
	 * Password最大試行回数を指定
	 */
	public FactorAuthenticationAttack.FactorAttackResult
	executeOneFactorPassword(
			String username,
			int maxAttemptsPassword) {

		NewAuthLabUser user =
				getUser(username);

		return factorAuthenticationAttack
				.executeOneFactorPassword(
						user.getPassword(),
						maxAttemptsPassword);
	}

	// =========================================================
	// 一要素認証
	// Email OTP
	// =========================================================

	public FactorAuthenticationAttack.FactorAttackResult
	executeOneFactorEmailOtp(
			String username,
			int maxAttempts) {

		NewAuthLabUser user =
				getUser(username);

		if (user.getEmail() == null
				|| user.getEmail().isBlank()) {

			throw new IllegalArgumentException(
					"指定されたユーザーにメールアドレスが登録されていません。");
		}

		return factorAuthenticationAttack
				.executeOneFactorEmailOtp(
						user.getEmail(),
						maxAttempts);
	}

	// =========================================================
	// 一要素認証
	// Email OTP
	// 実ログイン付き
	// =========================================================

	public OneFactorEmailOtpLoginResult
	executeOneFactorEmailOtpWithLogin(
			String username,
			int maxAttempts) {

		NewAuthLabUser user =
				getUser(username);

		if (user.getEmail() == null
				|| user.getEmail().isBlank()) {

			throw new IllegalArgumentException(
					"指定されたユーザーにメールアドレスが登録されていません。");
		}

		EmailOtpBruteForceAttack.AttackResult
		attackResult =
		emailOtpBruteForceAttack.execute(
				user.getEmail(),
				maxAttempts);

		return new OneFactorEmailOtpLoginResult(
				attackResult);
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// =========================================================

	/**
	 * 既存互換版
	 *
	 * Password      最大10000回
	 * Email OTP     最大1000000回
	 */
	public FactorAuthenticationAttack.FactorAttackResult
	executeTwoFactorPasswordEmailOtp(
			String username) {

		return executeTwoFactorPasswordEmailOtp(
				username,
				10_000,
				1_000_000);
	}

	/**
	 * PasswordとEmail OTPの最大試行回数を個別指定
	 *
	 * Password
	 *   ↓
	 * Email OTP
	 */
	public FactorAuthenticationAttack.FactorAttackResult
	executeTwoFactorPasswordEmailOtp(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsOtp) {

		NewAuthLabUser user =
				getUser(username);

		// =====================================================
		// ユーザーのPasswordハッシュを取得
		// =====================================================

		String passwordHash =
				user.getPassword();

		if (passwordHash == null
				|| passwordHash.isBlank()) {

			throw new IllegalArgumentException(
					"指定されたユーザーのPasswordが登録されていません。");
		}

		// =====================================================
		// 二要素認証攻撃本体
		//
		// Password総当たり
		// ↓
		// Email OTP総当たり
		// =====================================================

		return factorAuthenticationAttack
				.executeTwoFactorPasswordEmailOtp(
						username,
						passwordHash,
						maxAttemptsPassword,
						maxAttemptsOtp);
	}

	// =========================================================
	// 一段階ログイン結果
	// =========================================================

	public static class OneStageLoginResult {

		private final MultiStagePasswordBruteForceAttack
		.AttackResult attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public OneStageLoginResult(
				MultiStagePasswordBruteForceAttack
				.AttackResult attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public MultiStagePasswordBruteForceAttack.AttackResult
		getAttackResult() {

			return attackResult;
		}

		public boolean isLoginSuccess() {

			return loginSuccess;
		}

		public LoginResult getLoginResult() {

			return loginResult;
		}

		public boolean isSuccess() {

			return attackResult.isSuccess();
		}

		public String getPassword() {

			return attackResult.getPassword();
		}

		public int getAttemptCount() {

			return attackResult.getTotalAttempts();
		}
	}

	// =========================================================
	// 二段階ログイン結果
	// =========================================================

	public static class TwoStageLoginResult {

		private final MultiStagePasswordBruteForceAttack
		.AttackResult attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public TwoStageLoginResult(
				MultiStagePasswordBruteForceAttack
				.AttackResult attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public MultiStagePasswordBruteForceAttack.AttackResult
		getAttackResult() {

			return attackResult;
		}

		public boolean isLoginSuccess() {

			return loginSuccess;
		}

		public LoginResult getLoginResult() {

			return loginResult;
		}

		public boolean isSuccess() {

			return attackResult.isSuccess();
		}

		public String getPassword() {

			return attackResult.getPassword();
		}

		public String getPassword2() {

			return attackResult.getPassword2();
		}

		public int getAttemptCount() {

			return attackResult.getTotalAttempts();
		}
	}

	// =========================================================
	// 三段階ログイン結果
	// =========================================================

	public static class ThreeStageLoginResult {

		private final MultiStagePasswordBruteForceAttack
		.AttackResult attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public ThreeStageLoginResult(
				MultiStagePasswordBruteForceAttack
				.AttackResult attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public MultiStagePasswordBruteForceAttack.AttackResult
		getAttackResult() {

			return attackResult;
		}

		public boolean isLoginSuccess() {

			return loginSuccess;
		}

		public LoginResult getLoginResult() {

			return loginResult;
		}

		public boolean isSuccess() {

			return attackResult.isSuccess();
		}

		public String getPassword() {

			return attackResult.getPassword();
		}

		public String getPassword2() {

			return attackResult.getPassword2();
		}

		public String getPassword3() {

			return attackResult.getPassword3();
		}

		public int getAttemptCount() {

			return attackResult.getTotalAttempts();
		}
	}

	// =========================================================
	// 一要素 Email OTPログイン結果
	// =========================================================

	public static class OneFactorEmailOtpLoginResult {

		private final EmailOtpBruteForceAttack
		.AttackResult attackResult;

		public OneFactorEmailOtpLoginResult(
				EmailOtpBruteForceAttack
				.AttackResult attackResult) {

			this.attackResult =
					attackResult;
		}

		public EmailOtpBruteForceAttack.AttackResult
		getAttackResult() {

			return attackResult;
		}

		public boolean isLoginSuccess() {

			return attackResult.getLoginResult() != null
					&& attackResult
					.getLoginResult()
					.isSuccess();
		}

		public LoginResult getLoginResult() {

			return attackResult
					.getLoginResult();
		}

		public boolean isSuccess() {

			return attackResult.isSuccess();
		}

		public String getOtp() {

			return attackResult.getOtp();
		}

		public int getAttemptCount() {

			return attackResult.getAttemptCount();
		}

		public String getFinalUrl() {

			if (attackResult.getLoginResult() == null) {

				return null;
			}

			return attackResult
					.getLoginResult()
					.getFinalUrl();
		}

		public String getSessionCookie() {

			if (attackResult.getLoginResult() == null) {

				return null;
			}

			return attackResult
					.getLoginResult()
					.getSessionCookie();
		}
	}
}