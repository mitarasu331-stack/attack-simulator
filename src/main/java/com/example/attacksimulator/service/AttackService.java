package com.example.attacksimulator.service;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.attack.DictionaryPasswordAttack;
import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.RandomEmailOtpAttack;
import com.example.attacksimulator.attack.RandomPasswordAttack;
import com.example.attacksimulator.attack.RandomThreeStagePasswordAttack;
import com.example.attacksimulator.attack.RandomTwoFactorPasswordEmailOtpAttack;
import com.example.attacksimulator.attack.RandomTwoStagePasswordAttack;
import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;
import com.example.attacksimulator.model.NewAuthLabUser;
import com.example.attacksimulator.repository.NewAuthLabUserRepository;

@Service
public class AttackService {

	private final MultiStagePasswordBruteForceAttack multiStagePasswordBruteForceAttack;

	private final EmailOtpBruteForceAttack emailOtpBruteForceAttack;

	private final FactorAuthenticationAttack factorAuthenticationAttack;

	private final RandomPasswordAttack randomPasswordAttack;

	private final RandomTwoStagePasswordAttack randomTwoStagePasswordAttack;

	private final RandomThreeStagePasswordAttack randomThreeStagePasswordAttack;

	private final RandomEmailOtpAttack randomEmailOtpAttack;

	private final RandomTwoFactorPasswordEmailOtpAttack randomTwoFactorPasswordEmailOtpAttack;

	private final NewAuthLabUserRepository newAuthLabUserRepository;

	private final NewAuthLabLoginClient newAuthLabLoginClient;

	private final DictionaryPasswordAttack dictionaryPasswordAttack;

	public AttackService(

			MultiStagePasswordBruteForceAttack multiStagePasswordBruteForceAttack,

			EmailOtpBruteForceAttack emailOtpBruteForceAttack,

			FactorAuthenticationAttack factorAuthenticationAttack,

			RandomPasswordAttack randomPasswordAttack,

			RandomTwoStagePasswordAttack randomTwoStagePasswordAttack,

			RandomThreeStagePasswordAttack randomThreeStagePasswordAttack,

			RandomEmailOtpAttack randomEmailOtpAttack,

			RandomTwoFactorPasswordEmailOtpAttack randomTwoFactorPasswordEmailOtpAttack,

			NewAuthLabUserRepository newAuthLabUserRepository,

			NewAuthLabLoginClient newAuthLabLoginClient,

			DictionaryPasswordAttack dictionaryPasswordAttack) {

		this.multiStagePasswordBruteForceAttack =
				multiStagePasswordBruteForceAttack;

		this.emailOtpBruteForceAttack =
				emailOtpBruteForceAttack;

		this.factorAuthenticationAttack =
				factorAuthenticationAttack;

		this.randomPasswordAttack =
				randomPasswordAttack;

		this.randomTwoStagePasswordAttack =
				randomTwoStagePasswordAttack;

		this.randomThreeStagePasswordAttack =
				randomThreeStagePasswordAttack;

		this.randomEmailOtpAttack =
				randomEmailOtpAttack;

		this.randomTwoFactorPasswordEmailOtpAttack =
				randomTwoFactorPasswordEmailOtpAttack;

		this.newAuthLabUserRepository =
				newAuthLabUserRepository;

		this.newAuthLabLoginClient =
				newAuthLabLoginClient;

		this.dictionaryPasswordAttack =
				dictionaryPasswordAttack;
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
	// Password総当たり
	// =========================================================

	public MultiStagePasswordBruteForceAttack.AttackResult
	executeOneStage(
			String username) {

		return executeOneStage(
				username,
				10_000);
	}

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
	// Password総当たり＋実ログイン
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

		if (!attackResult.isSuccess()) {

			return new OneStageLoginResult(
					attackResult,
					false,
					null);
		}

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
	// 一段階認証
	// ランダム攻撃
	// =========================================================

	public RandomPasswordAttack.AttackResult
	executeRandomOneStage(
			String username) {

		return executeRandomOneStage(
				username,
				10_000);
	}

	public RandomPasswordAttack.AttackResult
	executeRandomOneStage(
			String username,
			int maxAttemptsPassword) {

		NewAuthLabUser user =
				getUser(username);

		return randomPasswordAttack
				.execute(
						user.getPassword(),
						maxAttemptsPassword);
	}

	// =========================================================
	// 一段階ランダム攻撃
	// 実ログイン付き
	// =========================================================

	public RandomOneStageLoginResult
	executeRandomOneStageWithLogin(
			String username) {

		return executeRandomOneStageWithLogin(
				username,
				10_000);
	}

	public RandomOneStageLoginResult
	executeRandomOneStageWithLogin(
			String username,
			int maxAttemptsPassword) {

		RandomPasswordAttack.AttackResult
		attackResult =
		executeRandomOneStage(
				username,
				maxAttemptsPassword);

		if (!attackResult.isSuccess()) {

			return new RandomOneStageLoginResult(
					attackResult,
					false,
					null);
		}

		LoginResult loginResult =
				newAuthLabLoginClient.loginOneStage(
						username,
						attackResult.getPassword());

		return new RandomOneStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// 二段階認証
	// Password → Password2
	// 総当たり
	// =========================================================

	public MultiStagePasswordBruteForceAttack.AttackResult
	executeTwoStage(
			String username) {

		return executeTwoStage(
				username,
				10_000,
				10_000);
	}

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

		if (!attackResult.isSuccess()) {

			return new TwoStageLoginResult(
					attackResult,
					false,
					null);
		}

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
	// 二段階認証
	// Password → Password2
	// ランダム攻撃
	// =========================================================

	public RandomTwoStagePasswordAttack.AttackResult
	executeRandomTwoStage(
			String username) {

		return executeRandomTwoStage(
				username,
				10_000,
				10_000);
	}

	public RandomTwoStagePasswordAttack.AttackResult
	executeRandomTwoStage(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2) {

		NewAuthLabUser user =
				getUser(username);

		return randomTwoStagePasswordAttack
				.execute(
						user.getPassword(),
						user.getPassword2(),
						maxAttemptsPassword,
						maxAttemptsPassword2);
	}

	// =========================================================
	// 二段階認証
	// ランダム攻撃＋実ログイン
	// =========================================================

	public RandomTwoStageLoginResult
	executeRandomTwoStageWithLogin(
			String username) {

		return executeRandomTwoStageWithLogin(
				username,
				10_000,
				10_000);
	}

	public RandomTwoStageLoginResult
	executeRandomTwoStageWithLogin(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2) {

		RandomTwoStagePasswordAttack.AttackResult
		attackResult =
		executeRandomTwoStage(
				username,
				maxAttemptsPassword,
				maxAttemptsPassword2);

		if (!attackResult.isSuccess()) {

			return new RandomTwoStageLoginResult(
					attackResult,
					false,
					null);
		}

		LoginResult loginResult =
				newAuthLabLoginClient.loginTwoStage(
						username,
						attackResult.getPassword(),
						attackResult.getPassword2());

		return new RandomTwoStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// 三段階認証
	// Password → Password2 → Password3
	// 総当たり
	// =========================================================

	public MultiStagePasswordBruteForceAttack.AttackResult
	executeThreeStage(
			String username) {

		return executeThreeStage(
				username,
				10_000,
				10_000,
				10_000);
	}

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

		if (!attackResult.isSuccess()) {

			return new ThreeStageLoginResult(
					attackResult,
					false,
					null);
		}

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
	// 三段階認証
	// Password → Password2 → Password3
	// ランダム攻撃
	// =========================================================

	public RandomThreeStagePasswordAttack.AttackResult
	executeRandomThreeStage(
			String username) {

		return executeRandomThreeStage(
				username,
				10_000,
				10_000,
				10_000);
	}

	public RandomThreeStagePasswordAttack.AttackResult
	executeRandomThreeStage(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2,
			int maxAttemptsPassword3) {

		NewAuthLabUser user =
				getUser(username);

		return randomThreeStagePasswordAttack
				.execute(
						user.getPassword(),
						user.getPassword2(),
						user.getPassword3(),
						maxAttemptsPassword,
						maxAttemptsPassword2,
						maxAttemptsPassword3);
	}

	// =========================================================
	// 三段階認証
	// ランダム攻撃＋実ログイン
	// =========================================================

	public RandomThreeStageLoginResult
	executeRandomThreeStageWithLogin(
			String username) {

		return executeRandomThreeStageWithLogin(
				username,
				10_000,
				10_000,
				10_000);
	}

	public RandomThreeStageLoginResult
	executeRandomThreeStageWithLogin(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsPassword2,
			int maxAttemptsPassword3) {

		RandomThreeStagePasswordAttack.AttackResult
		attackResult =
		executeRandomThreeStage(
				username,
				maxAttemptsPassword,
				maxAttemptsPassword2,
				maxAttemptsPassword3);

		if (!attackResult.isSuccess()) {

			return new RandomThreeStageLoginResult(
					attackResult,
					false,
					null);
		}

		LoginResult loginResult =
				newAuthLabLoginClient.loginThreeStage(
						username,
						attackResult.getPassword(),
						attackResult.getPassword2(),
						attackResult.getPassword3());

		return new RandomThreeStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// 一要素認証
	// Password
	// =========================================================

	public FactorAuthenticationAttack.FactorAttackResult
	executeOneFactorPassword(
			String username) {

		return executeOneFactorPassword(
				username,
				10_000);
	}

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
	// 総当たり
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
		emailOtpBruteForceAttack
		.execute(
				user.getEmail(),
				maxAttempts);

		return new OneFactorEmailOtpLoginResult(
				attackResult);
	}

	// =========================================================
	// 一要素認証
	// Email OTP
	// ランダム攻撃
	// =========================================================

	public RandomEmailOtpLoginResult
	executeRandomOneFactorEmailOtp(
			String username) {

		return executeRandomOneFactorEmailOtp(
				username,
				1_000_000);
	}

	public RandomEmailOtpLoginResult
	executeRandomOneFactorEmailOtp(
			String username,
			int maxAttempts) {

		NewAuthLabUser user =
				getUser(username);

		if (user.getEmail() == null
				|| user.getEmail().isBlank()) {

			throw new IllegalArgumentException(
					"指定されたユーザーにメールアドレスが登録されていません。");
		}

		// =====================================================
		// まずOTPを1回送信
		// =====================================================

		LoginResult sendResult =
				newAuthLabLoginClient.sendEmailOtp(
						user.getEmail());

		if (!sendResult.isRequestSuccess()) {

			return new RandomEmailOtpLoginResult(
					new RandomEmailOtpAttack.AttackResult(
							false,
							null,
							0),
					sendResult);
		}

		// =====================================================
		// OTPをランダム攻撃
		// =====================================================

		final LoginResult[] successfulLogin =
				new LoginResult[1];

		RandomEmailOtpAttack.AttackResult
		attackResult =
		randomEmailOtpAttack.execute(
				candidateOtp -> {

					LoginResult verifyResult =
							newAuthLabLoginClient
							.verifyEmailOtp(
									candidateOtp);

					if (verifyResult.isSuccess()) {

						successfulLogin[0] =
								verifyResult;

						return true;
					}

					return false;
				},
				maxAttempts);

		return new RandomEmailOtpLoginResult(
				attackResult,
				successfulLogin[0]);
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// 総当たり
	// =========================================================

	public FactorAuthenticationAttack.FactorAttackResult
	executeTwoFactorPasswordEmailOtp(
			String username) {

		return executeTwoFactorPasswordEmailOtp(
				username,
				10_000,
				1_000_000);
	}

	public FactorAuthenticationAttack.FactorAttackResult
	executeTwoFactorPasswordEmailOtp(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsOtp) {

		NewAuthLabUser user =
				getUser(username);

		String passwordHash =
				user.getPassword();

		if (passwordHash == null
				|| passwordHash.isBlank()) {

			throw new IllegalArgumentException(
					"指定されたユーザーのPasswordが登録されていません。");
		}

		return factorAuthenticationAttack
				.executeTwoFactorPasswordEmailOtp(
						username,
						passwordHash,
						maxAttemptsPassword,
						maxAttemptsOtp);
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// ランダム攻撃
	//
	// PasswordもOTPもランダム
	// =========================================================

	public RandomTwoFactorPasswordEmailOtpAttack.AttackResult
	executeRandomTwoFactorPasswordEmailOtp(
			String username) {

		return executeRandomTwoFactorPasswordEmailOtp(
				username,
				10_000,
				1_000_000);
	}

	public RandomTwoFactorPasswordEmailOtpAttack.AttackResult
	executeRandomTwoFactorPasswordEmailOtp(
			String username,
			int maxAttemptsPassword,
			int maxAttemptsOtp) {

		NewAuthLabUser user =
				getUser(username);

		if (user.getEmail() == null
				|| user.getEmail().isBlank()) {

			throw new IllegalArgumentException(
					"指定されたユーザーにメールアドレスが登録されていません。");
		}

		// =====================================================
		// Passwordが見つかったかを保持
		// =====================================================

		final String[] foundPassword =
				new String[1];

		// =====================================================
		// Email OTPの実ログイン結果
		// =====================================================

		final LoginResult[] successfulLogin =
				new LoginResult[1];

		// =====================================================
		// ランダム二要素攻撃
		// =====================================================

		RandomTwoFactorPasswordEmailOtpAttack.AttackResult
		attackResult =
		randomTwoFactorPasswordEmailOtpAttack
		.execute(
				maxAttemptsPassword,
				maxAttemptsOtp,

				// -----------------------------------------
				// Password verifier
				// -----------------------------------------

				candidatePassword -> {

					LoginResult loginResult =
							newAuthLabLoginClient
							.loginTwoFactorPassword(
									username,
									candidatePassword);

					if (loginResult.isSuccess()) {

						foundPassword[0] =
								candidatePassword;

						return true;
					}

					return false;
				},

				// -----------------------------------------
				// OTP verifier
				// -----------------------------------------

				candidateOtp -> {

					LoginResult verifyResult =
							newAuthLabLoginClient
							.verifyTwoFactorOtp(
									candidateOtp);

					if (verifyResult.isSuccess()) {

						successfulLogin[0] =
								verifyResult;

						return true;
					}

					return false;
				});

		return attackResult;
	}

	// =========================================================
	// 一段階ログイン結果
	// 総当たり
	// =========================================================

	public static class OneStageLoginResult {

		private final MultiStagePasswordBruteForceAttack.AttackResult
		attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public OneStageLoginResult(
				MultiStagePasswordBruteForceAttack.AttackResult
				attackResult,
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
	// 一段階ログイン結果
	// ランダム攻撃
	// =========================================================

	public static class RandomOneStageLoginResult {

		private final RandomPasswordAttack.AttackResult
		attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public RandomOneStageLoginResult(
				RandomPasswordAttack.AttackResult
				attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public RandomPasswordAttack.AttackResult
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

			return attackResult.getAttemptCount();
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

	// =========================================================
	// 二段階ログイン結果
	// 総当たり
	// =========================================================

	public static class TwoStageLoginResult {

		private final MultiStagePasswordBruteForceAttack.AttackResult
		attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public TwoStageLoginResult(
				MultiStagePasswordBruteForceAttack.AttackResult
				attackResult,
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
	// 二段階ログイン結果
	// ランダム攻撃
	// =========================================================

	public static class RandomTwoStageLoginResult {

		private final RandomTwoStagePasswordAttack.AttackResult
		attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public RandomTwoStageLoginResult(
				RandomTwoStagePasswordAttack.AttackResult
				attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public RandomTwoStagePasswordAttack.AttackResult
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

		public int getPasswordAttemptCount() {

			return attackResult
					.getPasswordAttemptCount();
		}

		public int getPassword2AttemptCount() {

			return attackResult
					.getPassword2AttemptCount();
		}

		public int getAttemptCount() {

			return attackResult.getAttemptCount();
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

	// =========================================================
	// 三段階ログイン結果
	// 総当たり
	// =========================================================

	public static class ThreeStageLoginResult {

		private final MultiStagePasswordBruteForceAttack.AttackResult
		attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public ThreeStageLoginResult(
				MultiStagePasswordBruteForceAttack.AttackResult
				attackResult,
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
	// 三段階ログイン結果
	// ランダム攻撃
	// =========================================================

	public static class RandomThreeStageLoginResult {

		private final RandomThreeStagePasswordAttack.AttackResult
		attackResult;

		private final boolean loginSuccess;

		private final LoginResult loginResult;

		public RandomThreeStageLoginResult(
				RandomThreeStagePasswordAttack.AttackResult
				attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public RandomThreeStagePasswordAttack.AttackResult
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

		public int getPasswordAttemptCount() {

			return attackResult
					.getPasswordAttemptCount();
		}

		public int getPassword2AttemptCount() {

			return attackResult
					.getPassword2AttemptCount();
		}

		public int getPassword3AttemptCount() {

			return attackResult
					.getPassword3AttemptCount();
		}

		public int getAttemptCount() {

			return attackResult.getAttemptCount();
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

	// =========================================================
	// 一要素 Email OTP
	// ランダム攻撃結果
	// =========================================================

	public static class RandomEmailOtpLoginResult {

		private final RandomEmailOtpAttack.AttackResult
		attackResult;

		private final LoginResult loginResult;

		public RandomEmailOtpLoginResult(
				RandomEmailOtpAttack.AttackResult
				attackResult,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginResult =
					loginResult;
		}

		public RandomEmailOtpAttack.AttackResult
		getAttackResult() {

			return attackResult;
		}

		public LoginResult getLoginResult() {

			return loginResult;
		}

		public boolean isSuccess() {

			return attackResult != null
					&& attackResult.isSuccess();
		}

		public boolean isLoginSuccess() {

			return loginResult != null
					&& loginResult.isSuccess();
		}

		public String getOtp() {

			if (attackResult == null) {

				return null;
			}

			return attackResult.getOtp();
		}

		public int getAttemptCount() {

			if (attackResult == null) {

				return 0;
			}

			return attackResult.getAttemptCount();
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

	// =========================================================
	// 一要素 Email OTPログイン結果
	// 総当たり
	// =========================================================

	public static class OneFactorEmailOtpLoginResult {

		private final EmailOtpBruteForceAttack.AttackResult
		attackResult;

		public OneFactorEmailOtpLoginResult(
				EmailOtpBruteForceAttack.AttackResult
				attackResult) {

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

	// =========================================================
	// 辞書攻撃
	// =========================================================

	public DictionaryLoginResult
	executeDictionaryWithLogin(
			String username,
			String authMethod,
			int maxAttemptsPassword,
			int maxAttemptsPassword2,
			int maxAttemptsPassword3) {

		final LoginResult[] successfulLogin =
				new LoginResult[1];

		DictionaryPasswordAttack.AttackResult result;

		// =====================================================
		// 一段階
		// =====================================================

		if ("one-stage-dictionary"
				.equals(authMethod)) {

			result =
					dictionaryPasswordAttack
					.executeOneStage(
							maxAttemptsPassword,
							password -> {

								LoginResult loginResult =
										newAuthLabLoginClient
										.loginOneStage(
												username,
												password);

								if (loginResult.isSuccess()) {

									successfulLogin[0] =
											loginResult;

									return true;
								}

								return false;
							});
		}

		// =====================================================
		// 二段階
		// Password → Password2
		// =====================================================

		else if ("two-stage-dictionary"
				.equals(authMethod)) {

			final String[] foundPassword =
					new String[1];

			result =
					dictionaryPasswordAttack
					.executeTwoStage(
							maxAttemptsPassword,
							maxAttemptsPassword2,
							(stage, candidate) -> {

								if (stage == 1) {

									LoginResult loginResult =
											newAuthLabLoginClient
											.loginOneStage(
													username,
													candidate);

									if (loginResult.isSuccess()) {

										foundPassword[0] =
												candidate;

										return true;
									}

									return false;
								}

								if (stage == 2) {

									if (foundPassword[0] == null) {

										return false;
									}

									LoginResult loginResult =
											newAuthLabLoginClient
											.loginTwoStage(
													username,
													foundPassword[0],
													candidate);

									if (loginResult.isSuccess()) {

										successfulLogin[0] =
												loginResult;

										return true;
									}

									return false;
								}

								return false;
							});
		}

		// =====================================================
		// 三段階
		// Password → Password2 → Password3
		// =====================================================

		else if ("three-stage-dictionary"
				.equals(authMethod)) {

			final String[] foundPassword =
					new String[1];

			final String[] foundPassword2 =
					new String[1];

			result =
					dictionaryPasswordAttack
					.executeThreeStage(
							maxAttemptsPassword,
							maxAttemptsPassword2,
							maxAttemptsPassword3,
							(stage, candidate) -> {

								if (stage == 1) {

									LoginResult loginResult =
											newAuthLabLoginClient
											.loginOneStage(
													username,
													candidate);

									if (loginResult.isSuccess()) {

										foundPassword[0] =
												candidate;

										return true;
									}

									return false;
								}

								if (stage == 2) {

									if (foundPassword[0] == null) {

										return false;
									}

									LoginResult loginResult =
											newAuthLabLoginClient
											.loginTwoStage(
													username,
													foundPassword[0],
													candidate);

									if (loginResult.isSuccess()) {

										foundPassword2[0] =
												candidate;

										return true;
									}

									return false;
								}

								if (stage == 3) {

									if (foundPassword[0] == null
											|| foundPassword2[0] == null) {

										return false;
									}

									LoginResult loginResult =
											newAuthLabLoginClient
											.loginThreeStage(
													username,
													foundPassword[0],
													foundPassword2[0],
													candidate);

									if (loginResult.isSuccess()) {

										successfulLogin[0] =
												loginResult;

										return true;
									}

									return false;
								}

								return false;
							});
		}

		else {

			throw new IllegalArgumentException(
					"不正な辞書攻撃方式です。");
		}

		return new DictionaryLoginResult(
				result,
				successfulLogin[0]);
	}

	// =========================================================
	// 辞書攻撃ログイン結果
	// =========================================================

	public static class DictionaryLoginResult {

		private final DictionaryPasswordAttack.AttackResult
		attackResult;

		private final LoginResult loginResult;

		public DictionaryLoginResult(
				DictionaryPasswordAttack.AttackResult attackResult,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginResult =
					loginResult;
		}

		public DictionaryPasswordAttack.AttackResult
		getAttackResult() {

			return attackResult;
		}

		public boolean isSuccess() {

			return attackResult != null
					&& attackResult.isSuccess();
		}

		public boolean isLoginSuccess() {

			return loginResult != null
					&& loginResult.isSuccess();
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

		public int getPasswordAttemptCount() {

			return attackResult
					.getPasswordAttemptCount();
		}

		public int getPassword2AttemptCount() {

			return attackResult
					.getPassword2AttemptCount();
		}

		public int getPassword3AttemptCount() {

			return attackResult
					.getPassword3AttemptCount();
		}

		public String getFinalUrl() {

			if (loginResult == null) {

				return null;
			}

			return loginResult.getFinalUrl();
		}

		public LoginResult getLoginResult() {

			return loginResult;
		}
	}
}