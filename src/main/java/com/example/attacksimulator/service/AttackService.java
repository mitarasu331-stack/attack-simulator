package com.example.attacksimulator.service;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
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
			MultiStagePasswordBruteForceAttack multiStagePasswordBruteForceAttack,
			EmailOtpBruteForceAttack emailOtpBruteForceAttack,
			FactorAuthenticationAttack factorAuthenticationAttack,
			NewAuthLabUserRepository newAuthLabUserRepository,
			NewAuthLabLoginClient newAuthLabLoginClient) {

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
	// 対象ユーザー取得
	// =========================================================

	private NewAuthLabUser getUser(
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
	// ID + Password
	// =========================================================

	public AttackResult executeOneStage(
			String username) {

		NewAuthLabUser user =
				getUser(username);

		return multiStagePasswordBruteForceAttack
				.executeOneStage(
						user.getPassword());
	}

	// =========================================================
	// 一段階認証
	// 総当たり成功後にnewauthlabへ実ログイン
	// =========================================================

	public OneStageLoginResult executeOneStageWithLogin(
			String username) {

		AttackResult attackResult =
				executeOneStage(username);

		if (!attackResult.isSuccess()) {

			return new OneStageLoginResult(
					attackResult,
					false,
					null);
		}

		String password =
				attackResult.getPassword();

		LoginResult loginResult =
				newAuthLabLoginClient
				.loginOneStage(
						username,
						password);

		return new OneStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// 二段階認証
	// Password → Password2
	// =========================================================

	public AttackResult executeTwoStage(
			String username) {

		NewAuthLabUser user =
				getUser(username);

		return multiStagePasswordBruteForceAttack
				.executeTwoStage(
						user.getPassword(),
						user.getPassword2());
	}

	// =========================================================
	// 二段階認証
	// 総当たり成功後にnewauthlabへ実ログイン
	// =========================================================

	public TwoStageLoginResult executeTwoStageWithLogin(
			String username) {

		AttackResult attackResult =
				executeTwoStage(username);

		/*
		 * Password または Password2 の
		 * 総当たりに失敗した場合
		 */
		if (!attackResult.isSuccess()) {

			return new TwoStageLoginResult(
					attackResult,
					false,
					null);
		}

		/*
		 * 総当たりで発見した
		 * Password / Password2
		 */
		String password =
				attackResult.getPassword();

		String password2 =
				attackResult.getPassword2();

		/*
		 * newauthlabで実際の二段階ログイン
		 */
		LoginResult loginResult =
				newAuthLabLoginClient
				.loginTwoStage(
						username,
						password,
						password2);

		return new TwoStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// 三段階認証
	// Password → Password2 → Password3
	// =========================================================

	public AttackResult executeThreeStage(
			String username) {

		NewAuthLabUser user =
				getUser(username);

		return multiStagePasswordBruteForceAttack
				.executeThreeStage(
						user.getPassword(),
						user.getPassword2(),
						user.getPassword3());
	}

	// =========================================================
	// 三段階認証
	// 総当たり成功後にnewauthlabへ実ログイン
	// =========================================================

	public ThreeStageLoginResult executeThreeStageWithLogin(
			String username) {

		// -----------------------------------------------------
		// 三段階の総当たりを実行
		// -----------------------------------------------------

		AttackResult attackResult =
				executeThreeStage(username);

		// -----------------------------------------------------
		// Password / Password2 / Password3 の
		// いずれかの突破に失敗した場合
		// -----------------------------------------------------

		if (!attackResult.isSuccess()) {

			return new ThreeStageLoginResult(
					attackResult,
					false,
					null);
		}

		// -----------------------------------------------------
		// 総当たりで発見した認証情報
		// -----------------------------------------------------

		String password =
				attackResult.getPassword();

		String password2 =
				attackResult.getPassword2();

		String password3 =
				attackResult.getPassword3();

		// -----------------------------------------------------
		// newauthlabで実際の三段階ログイン
		// -----------------------------------------------------

		LoginResult loginResult =
				newAuthLabLoginClient
				.loginThreeStage(
						username,
						password,
						password2,
						password3);

		return new ThreeStageLoginResult(
				attackResult,
				loginResult.isSuccess(),
				loginResult);
	}

	// =========================================================
	// Password総当たり
	// =========================================================

	public PasswordBruteForceAttack.AttackResult
	executePasswordBruteForce(
			String username) {

		NewAuthLabUser user =
				getUser(username);

		return passwordBruteForceAttack
				.execute(
						user.getPassword());
	}

	// =========================================================
	// Email OTP総当たり
	// =========================================================

	public EmailOtpBruteForceAttack.AttackResult
	executeEmailOtpBruteForce(
			int maxAttempts) {

		return emailOtpBruteForceAttack
				.execute(maxAttempts);
	}

	// =========================================================
	// 一要素認証 Password
	// =========================================================

	public FactorAuthenticationAttack.FactorAttackResult
	executeOneFactorPassword(
			String username) {

		NewAuthLabUser user =
				getUser(username);

		return factorAuthenticationAttack
				.executeOneFactorPassword(
						user.getPassword());
	}

	// =========================================================
	// 一要素認証 Email OTP
	// =========================================================

	public FactorAuthenticationAttack.FactorAttackResult
	executeOneFactorEmailOtp(
			int maxAttempts) {

		return factorAuthenticationAttack
				.executeOneFactorEmailOtp(
						maxAttempts);
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// =========================================================

	public FactorAuthenticationAttack.FactorAttackResult
	executeTwoFactorPasswordEmailOtp(
			String username,
			int maxOtpAttempts) {

		NewAuthLabUser user =
				getUser(username);

		return factorAuthenticationAttack
				.executeTwoFactorPasswordEmailOtp(
						user.getPassword(),
						maxOtpAttempts);
	}

	// =========================================================
	// 一段階実ログイン結果
	// =========================================================

	public static class OneStageLoginResult {

		private final AttackResult attackResult;
		private final boolean loginSuccess;
		private final LoginResult loginResult;

		public OneStageLoginResult(
				AttackResult attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public AttackResult getAttackResult() {
			return attackResult;
		}

		public boolean isLoginSuccess() {
			return loginSuccess;
		}

		public LoginResult getLoginResult() {
			return loginResult;
		}
	}

	// =========================================================
	// 二段階実ログイン結果
	// =========================================================

	public static class TwoStageLoginResult {

		private final AttackResult attackResult;
		private final boolean loginSuccess;
		private final LoginResult loginResult;

		public TwoStageLoginResult(
				AttackResult attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public AttackResult getAttackResult() {
			return attackResult;
		}

		public boolean isLoginSuccess() {
			return loginSuccess;
		}

		public LoginResult getLoginResult() {
			return loginResult;
		}
	}

	// =========================================================
	// 三段階実ログイン結果
	// =========================================================

	public static class ThreeStageLoginResult {

		private final AttackResult attackResult;
		private final boolean loginSuccess;
		private final LoginResult loginResult;

		public ThreeStageLoginResult(
				AttackResult attackResult,
				boolean loginSuccess,
				LoginResult loginResult) {

			this.attackResult =
					attackResult;

			this.loginSuccess =
					loginSuccess;

			this.loginResult =
					loginResult;
		}

		public AttackResult getAttackResult() {
			return attackResult;
		}

		public boolean isLoginSuccess() {
			return loginSuccess;
		}

		public LoginResult getLoginResult() {
			return loginResult;
		}
	}
}