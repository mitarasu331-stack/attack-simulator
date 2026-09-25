package com.example.attacksimulator.controller;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.PasswordBruteForceAttack;
import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.model.ExperimentResult;
import com.example.attacksimulator.service.AttackService;
import com.example.attacksimulator.service.ExperimentResultService;
import com.example.attacksimulator.service.NewAuthLabUserService;

@Controller
public class AttackController {

	private final AttackService attackService;

	private final ExperimentResultService experimentResultService;

	private final NewAuthLabUserService newAuthLabUserService;

	private final NewAuthLabLoginClient newAuthLabLoginClient;

	public AttackController(
			AttackService attackService,
			ExperimentResultService experimentResultService,
			NewAuthLabUserService newAuthLabUserService,
			NewAuthLabLoginClient newAuthLabLoginClient) {

		this.attackService =
				attackService;

		this.experimentResultService =
				experimentResultService;

		this.newAuthLabUserService =
				newAuthLabUserService;

		this.newAuthLabLoginClient =
				newAuthLabLoginClient;
	}

	// =========================================================
	// 攻撃実験画面
	// =========================================================

	@GetMapping("/")
	public String index(Model model) {

		List<String> usernames =
				newAuthLabUserService
				.getAllUsernames();

		model.addAttribute(
				"usernames",
				usernames);

		return "attack";
	}

	// =========================================================
	// パスワード攻撃
	// 旧一段階認証用
	// =========================================================

	@PostMapping("/attack/password")
	public String attackPassword(
			@RequestParam("username") String username,
			@RequestParam("authMethod") String authMethod,
			@RequestParam(
					value = "maxAttemptsPassword",
					required = false,
					defaultValue = "10000")
			int maxAttemptsPassword,
			RedirectAttributes redirectAttributes,
			Model model) {

		long startTime =
				System.nanoTime();

		try {

			maxAttemptsPassword =
					clampPasswordAttempts(
							maxAttemptsPassword);

			// =================================================
			// Password総当たり
			// =================================================

			PasswordBruteForceAttack.AttackResult result =
					attackService.executePasswordBruteForce(
							username,
							maxAttemptsPassword);

			long attackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			// =================================================
			// newauthlabで実ログイン
			// =================================================

			boolean realLoginSuccess = false;

			if (result.isSuccess()) {

				NewAuthLabLoginClient.LoginResult loginResult =
						newAuthLabLoginClient.loginOneStage(
								username,
								result.getPassword());

				realLoginSuccess =
						loginResult.isSuccess();

				System.out.println(
						"===== 一段階実ログイン結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ result.getPassword());

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"HTTP Status = "
								+ loginResult.getStatusCode());

				System.out.println(
						"Final URL = "
								+ loginResult.getFinalUrl());

				System.out.println(
						"================================");
			}

			// =================================================
			// 結果保存
			// =================================================

			experimentResultService.addResult(
					username,
					authMethod,
					"ID + Password",
					String.valueOf(
							maxAttemptsPassword),
					result.getAttemptCount(),
					result.isSuccess(),
					result.getPassword(),
					attackTimeMs);

			// =================================================
			// 実ログイン成功
			// =================================================

			if (result.isSuccess()
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						result.getPassword());

				return "login-redirect";
			}

			// =================================================
			// 結果画面
			// =================================================

			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"success",
					result.isSuccess());

			redirectAttributes.addFlashAttribute(
					"password",
					result.getPassword());

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					result.getAttemptCount());

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"攻撃中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
	}

	// =========================================================
	// 多段階認証
	// 一段階 / 二段階 / 三段階
	// =========================================================

	@PostMapping("/attack/multi-stage")
	public String attackMultiStage(
			@RequestParam("username") String username,
			@RequestParam("authMethod") String authMethod,

			@RequestParam(
					value = "maxAttemptsPassword",
					required = false,
					defaultValue = "10000")
			int maxAttemptsPassword,

			@RequestParam(
					value = "maxAttemptsPassword2",
					required = false,
					defaultValue = "10000")
			int maxAttemptsPassword2,

			@RequestParam(
					value = "maxAttemptsPassword3",
					required = false,
					defaultValue = "10000")
			int maxAttemptsPassword3,

			RedirectAttributes redirectAttributes,
			Model model) {

		long startTime =
				System.nanoTime();

		try {

			// =================================================
			// 試行回数を制限
			// =================================================

			maxAttemptsPassword =
					clampPasswordAttempts(
							maxAttemptsPassword);

			maxAttemptsPassword2 =
					clampPasswordAttempts(
							maxAttemptsPassword2);

			maxAttemptsPassword3 =
					clampPasswordAttempts(
							maxAttemptsPassword3);

			MultiStagePasswordBruteForceAttack.AttackResult result;

			boolean realLoginSuccess = false;

			String maxAttemptCount;


			// =================================================
			// 一段階認証
			// Password
			// =================================================

			if ("one-stage".equals(authMethod)) {

				AttackService.OneStageLoginResult
				oneStageResult =
				attackService
				.executeOneStageWithLogin(
						username,
						maxAttemptsPassword);

				result =
						oneStageResult.getAttackResult();

				realLoginSuccess =
						oneStageResult.isLoginSuccess();

				maxAttemptCount =
						String.valueOf(
								maxAttemptsPassword);

				System.out.println(
						"===== 一段階実ログイン結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ result.getPassword());

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"================================");
			}


			// =================================================
			// 二段階認証
			// Password → Password2
			// =================================================

			else if ("two-stage".equals(authMethod)) {

				AttackService.TwoStageLoginResult
				twoStageResult =
				attackService
				.executeTwoStageWithLogin(
						username,
						maxAttemptsPassword,
						maxAttemptsPassword2);

				result =
						twoStageResult.getAttackResult();

				realLoginSuccess =
						twoStageResult.isLoginSuccess();

				maxAttemptCount =
						maxAttemptsPassword
						+ " → "
						+ maxAttemptsPassword2;

				System.out.println(
						"===== 二段階実ログイン結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ result.getPassword());

				System.out.println(
						"password2 = "
								+ result.getPassword2());

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"================================");
			}


			// =================================================
			// 三段階認証
			// Password → Password2 → Password3
			// =================================================

			else if ("three-stage".equals(authMethod)) {

				AttackService.ThreeStageLoginResult
				threeStageResult =
				attackService
				.executeThreeStageWithLogin(
						username,
						maxAttemptsPassword,
						maxAttemptsPassword2,
						maxAttemptsPassword3);

				result =
						threeStageResult.getAttackResult();

				realLoginSuccess =
						threeStageResult.isLoginSuccess();

				maxAttemptCount =
						maxAttemptsPassword
						+ " → "
						+ maxAttemptsPassword2
						+ " → "
						+ maxAttemptsPassword3;

				System.out.println(
						"===== 三段階実ログイン結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ result.getPassword());

				System.out.println(
						"password2 = "
								+ result.getPassword2());

				System.out.println(
						"password3 = "
								+ result.getPassword3());

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"================================");
			}


			// =================================================
			// 不正な認証方式
			// =================================================

			else {

				throw new IllegalArgumentException(
						"不正な認証方式です。");
			}


			long attackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;


			// =================================================
			// 認証情報
			// =================================================

			String credential =
					createMultiStageCredential(
							result);


			// =================================================
			// 認証構成
			// =================================================

			String configuration =
					createMultiStageConfiguration(
							result);


			// =================================================
			// 結果保存
			// =================================================

			experimentResultService.addResult(
					username,
					authMethod,
					configuration,
					maxAttemptCount,
					result.getTotalAttempts(),
					result.isSuccess(),
					credential,
					attackTimeMs);


			// =================================================
			// 一段階
			// 実ログイン成功
			// =================================================

			if ("one-stage".equals(authMethod)
					&& result.isSuccess()
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						result.getPassword());

				return "login-redirect";
			}


			// =================================================
			// 二段階
			// 実ログイン成功
			// =================================================

			if ("two-stage".equals(authMethod)
					&& result.isSuccess()
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						result.getPassword());

				model.addAttribute(
						"password2",
						result.getPassword2());

				return "two-stage-login-redirect";
			}


			// =================================================
			// 三段階
			// 実ログイン成功
			// =================================================

			if ("three-stage".equals(authMethod)
					&& result.isSuccess()
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						result.getPassword());

				model.addAttribute(
						"password2",
						result.getPassword2());

				model.addAttribute(
						"password3",
						result.getPassword3());

				return "three-stage-login-redirect";
			}


			// =================================================
			// result.html
			// =================================================

			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					result.getTotalAttempts());

			redirectAttributes.addFlashAttribute(
					"success",
					result.isSuccess());

			redirectAttributes.addFlashAttribute(
					"password",
					result.getPassword());

			redirectAttributes.addFlashAttribute(
					"password2",
					result.getPassword2());

			redirectAttributes.addFlashAttribute(
					"password3",
					result.getPassword3());

			redirectAttributes.addFlashAttribute(
					"otp",
					null);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			redirectAttributes.addFlashAttribute(
					"message",
					result.isSuccess()
					? "認証突破に成功しました。"
							: "認証突破に失敗しました。");

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					e.getMessage());
		}

		return "redirect:/result";
	}

	// =========================================================
	// 要素認証攻撃
	// =========================================================

	@PostMapping("/attack/factor")
	public String attackFactor(
			@RequestParam("username") String username,
			@RequestParam("authMethod") String authMethod,

			@RequestParam(
					value = "maxAttemptsPassword",
					required = false,
					defaultValue = "10000")
			int maxAttemptsPassword,

			@RequestParam(
					value = "maxAttempts",
					required = false,
					defaultValue = "1000000")
			int maxAttempts,

			RedirectAttributes redirectAttributes,
			Model model) {

		long startTime =
				System.nanoTime();

		try {

			// =================================================
			// 一要素 Password
			// =================================================

			if ("one-factor-password"
					.equals(authMethod)) {

				maxAttemptsPassword =
						clampPasswordAttempts(
								maxAttemptsPassword);

				FactorAuthenticationAttack.FactorAttackResult
				result =
				attackService
				.executeOneFactorPassword(
						username,
						maxAttemptsPassword);

				long attackTimeMs =
						(System.nanoTime() - startTime)
						/ 1_000_000;

				String maxAttemptCount =
						String.valueOf(
								maxAttemptsPassword);

				String credential =
						createFactorCredential(
								result);

				experimentResultService.addResult(
						username,
						result.getAuthMethod(),
						result.getAuthenticationConfiguration(),
						maxAttemptCount,
						result.getAttemptCount(),
						result.isSuccess(),
						credential,
						attackTimeMs);

				// =================================================
				// 実ログイン
				// =================================================

				boolean realLoginSuccess = false;

				if (result.isSuccess()) {

					NewAuthLabLoginClient.LoginResult loginResult =
							newAuthLabLoginClient.loginOneStage(
									username,
									result.getPassword());

					realLoginSuccess =
							loginResult.isSuccess();

					System.out.println(
							"===== 一要素Password実ログイン =====");

					System.out.println(
							"username = "
									+ username);

					System.out.println(
							"password = "
									+ result.getPassword());

					System.out.println(
							"実ログイン成功 = "
									+ realLoginSuccess);

					System.out.println(
							"====================================");

					if (realLoginSuccess) {

						model.addAttribute(
								"username",
								username);

						model.addAttribute(
								"password",
								result.getPassword());

						return "login-redirect";
					}
				}

				// =================================================
				// 結果画面
				// =================================================

				redirectAttributes.addFlashAttribute(
						"authMethod",
						authMethod);

				redirectAttributes.addFlashAttribute(
						"attemptCount",
						result.getAttemptCount());

				redirectAttributes.addFlashAttribute(
						"success",
						result.isSuccess());

				redirectAttributes.addFlashAttribute(
						"password",
						result.getPassword());

				redirectAttributes.addFlashAttribute(
						"otp",
						null);

				redirectAttributes.addFlashAttribute(
						"password2",
						null);

				redirectAttributes.addFlashAttribute(
						"password3",
						null);

				redirectAttributes.addFlashAttribute(
						"realLoginSuccess",
						realLoginSuccess);

				redirectAttributes.addFlashAttribute(
						"message",
						result.isSuccess()
						? "認証突破に成功しました。"
								: "認証突破に失敗しました。");

				return "redirect:/result";
			}


			// =================================================
			// 一要素 Email OTP
			// =================================================

			if ("one-factor-email-otp"
					.equals(authMethod)) {

				maxAttempts =
						clampOtpAttempts(
								maxAttempts);

				AttackService.OneFactorEmailOtpLoginResult
				emailOtpResult =
				attackService
				.executeOneFactorEmailOtpWithLogin(
						username,
						maxAttempts);

				long attackTimeMs =
						(System.nanoTime() - startTime)
						/ 1_000_000;

				String maxAttemptCount =
						String.valueOf(
								maxAttempts);

				String credential =
						emailOtpResult.getOtp();

				experimentResultService.addResult(
						username,
						"one-factor-email-otp",
						"ID + Email OTP",
						maxAttemptCount,
						emailOtpResult.getAttemptCount(),
						emailOtpResult.isSuccess(),
						credential,
						attackTimeMs);

				// =================================================
				// OTP突破＋実ログイン成功
				// =================================================

				if (emailOtpResult.isSuccess()
						&& emailOtpResult.isLoginSuccess()
						&& emailOtpResult.getLoginResult() != null) {

					String finalUrl =
							emailOtpResult
							.getLoginResult()
							.getFinalUrl();

					System.out.println(
							"===== Email OTP実ログイン =====");

					System.out.println(
							"username = "
									+ username);

					System.out.println(
							"OTP = "
									+ emailOtpResult.getOtp());

					System.out.println(
							"最大試行回数 = "
									+ maxAttemptCount);

					System.out.println(
							"ticket URL = "
									+ finalUrl);

					System.out.println(
							"================================");

					/*
					 * newauthlab側で発行された
					 * ワンタイムticketをブラウザから使用
					 */
					if (finalUrl != null
							&& !finalUrl.isBlank()) {

						return "redirect:" + finalUrl;
					}
				}

				// =================================================
				// OTP結果画面
				// =================================================

				redirectAttributes.addFlashAttribute(
						"authMethod",
						authMethod);

				redirectAttributes.addFlashAttribute(
						"attemptCount",
						emailOtpResult.getAttemptCount());

				redirectAttributes.addFlashAttribute(
						"success",
						emailOtpResult.isSuccess());

				redirectAttributes.addFlashAttribute(
						"password",
						null);

				redirectAttributes.addFlashAttribute(
						"otp",
						emailOtpResult.getOtp());

				redirectAttributes.addFlashAttribute(
						"password2",
						null);

				redirectAttributes.addFlashAttribute(
						"password3",
						null);

				redirectAttributes.addFlashAttribute(
						"realLoginSuccess",
						emailOtpResult.isLoginSuccess());

				redirectAttributes.addFlashAttribute(
						"message",
						emailOtpResult.isSuccess()
						? "Email OTPの認証突破に成功しました。"
								: "Email OTPの認証突破に失敗しました。");

				return "redirect:/result";
			}


			// =================================================
			// 二要素認証
			// Password → Email OTP
			// =================================================

			if ("two-factor-password-email-otp"
					.equals(authMethod)) {

				// -------------------------------------------------
				// Password最大試行回数
				// -------------------------------------------------

				maxAttemptsPassword =
						clampPasswordAttempts(
								maxAttemptsPassword);

				// -------------------------------------------------
				// Email OTP最大試行回数
				// -------------------------------------------------

				maxAttempts =
						clampOtpAttempts(
								maxAttempts);

				// -------------------------------------------------
				// 二要素認証攻撃実行
				// -------------------------------------------------

				FactorAuthenticationAttack.FactorAttackResult
				result =
				attackService
				.executeTwoFactorPasswordEmailOtp(
						username,
						maxAttemptsPassword,
						maxAttempts);

				long attackTimeMs =
						(System.nanoTime() - startTime)
						/ 1_000_000;

				// -------------------------------------------------
				// 最大攻撃試行回数
				//
				// 例：
				// 10000 → 1000000
				// -------------------------------------------------

				String maxAttemptCount =
						maxAttemptsPassword
						+ " → "
						+ maxAttempts;

				// -------------------------------------------------
				// 突破した認証情報
				//
				// 例：
				// 1111 → 123456
				// -------------------------------------------------

				String credential =
						createFactorCredential(
								result);

				// -------------------------------------------------
				// 実ログイン結果
				// -------------------------------------------------

				boolean realLoginSuccess =
						result.isLoginSuccess();

				System.out.println(
						"========================================");

				System.out.println(
						"===== 二要素認証 実ログイン結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ result.getPassword());

				System.out.println(
						"OTP = "
								+ result.getOtp());

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"実攻撃試行回数 = "
								+ result.getAttemptCount());

				System.out.println(
						"OTP実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"Final URL = "
								+ result.getFinalUrl());

				System.out.println(
						"========================================");

				// -------------------------------------------------
				// 結果保存
				// -------------------------------------------------

				experimentResultService.addResult(
						username,
						result.getAuthMethod(),
						result.getAuthenticationConfiguration(),
						maxAttemptCount,
						result.getAttemptCount(),
						result.isSuccess(),
						credential,
						attackTimeMs);

				// -------------------------------------------------
				// 二要素認証成功
				//
				// newauthlabから返されたticket URLへ
				// ブラウザ自身を移動させる。
				// -------------------------------------------------

				if (result.isSuccess()
						&& realLoginSuccess
						&& result.getFinalUrl() != null
						&& !result.getFinalUrl().isBlank()) {

					System.out.println(
							"二要素認証成功"
									+ " → newauthlabへ移動します。");

					return "redirect:"
					+ result.getFinalUrl();
				}

				// -------------------------------------------------
				// 結果画面
				// -------------------------------------------------

				redirectAttributes.addFlashAttribute(
						"authMethod",
						authMethod);

				redirectAttributes.addFlashAttribute(
						"attemptCount",
						result.getAttemptCount());

				redirectAttributes.addFlashAttribute(
						"success",
						result.isSuccess());

				redirectAttributes.addFlashAttribute(
						"password",
						result.getPassword());

				redirectAttributes.addFlashAttribute(
						"otp",
						result.getOtp());

				redirectAttributes.addFlashAttribute(
						"password2",
						null);

				redirectAttributes.addFlashAttribute(
						"password3",
						null);

				redirectAttributes.addFlashAttribute(
						"realLoginSuccess",
						realLoginSuccess);

				redirectAttributes.addFlashAttribute(
						"maxAttemptCount",
						maxAttemptCount);

				redirectAttributes.addFlashAttribute(
						"message",
						result.isSuccess()
						? "二要素認証の突破に成功しました。"
								: "二要素認証の突破に失敗しました。");

				return "redirect:/result";
			}


			// =================================================
			// 不正な認証方式
			// =================================================

			throw new IllegalArgumentException(
					"不正な認証方式です。");

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"攻撃中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
	}

	// =========================================================
	// 1回の攻撃結果画面
	// =========================================================

	@GetMapping("/result")
	public String result(Model model) {

		ExperimentResult result =
				experimentResultService
				.getLatestResult();

		if (result == null) {

			model.addAttribute(
					"error",
					"実験結果がありません");

			return "result";
		}

		String authMethod =
				result.getAuthMethod();

		model.addAttribute(
				"authMethod",
				authMethod);

		model.addAttribute(
				"attemptCount",
				result.getAttemptCount());

		model.addAttribute(
				"success",
				result.isSuccess());

		// =====================================================
		// 初期化
		// =====================================================

		model.addAttribute(
				"password",
				null);

		model.addAttribute(
				"password2",
				null);

		model.addAttribute(
				"password3",
				null);

		model.addAttribute(
				"otp",
				null);

		// =====================================================
		// 突破した認証情報
		// =====================================================

		String credential =
				result.getCredential();

		if (credential != null
				&& !credential.isBlank()) {

			// -------------------------------------------------
			// Email OTP
			// -------------------------------------------------

			if ("one-factor-email-otp"
					.equals(authMethod)) {

				model.addAttribute(
						"otp",
						credential);

			} else {

				String[] credentials =
						credential.split(" → ");

				if (credentials.length >= 1) {

					model.addAttribute(
							"password",
							credentials[0]);
				}

				if (credentials.length >= 2) {

					model.addAttribute(
							"password2",
							credentials[1]);
				}

				if (credentials.length >= 3) {

					model.addAttribute(
							"password3",
							credentials[2]);
				}
			}
		}

		model.addAttribute(
				"result",
				result);

		return "result";
	}

	// =========================================================
	// 実ログイン画面
	// =========================================================

	@GetMapping("/attack/real-login")
	public String realLogin(
			@ModelAttribute("username")
			String username,
			@ModelAttribute("password")
			String password,
			Model model) {

		model.addAttribute(
				"username",
				username);

		model.addAttribute(
				"password",
				password);

		return "login-redirect";
	}

	// =========================================================
	// 実験結果一覧
	// =========================================================

	@GetMapping("/results")
	public String results(
			@RequestParam(
					value = "authMethod",
					required = false)
			String authMethod,
			Model model) {

		List<ExperimentResult> results;

		if (authMethod == null
				|| authMethod.isBlank()
				|| "all".equals(authMethod)) {

			results =
					experimentResultService
					.getAllResults();

		} else {

			results =
					experimentResultService
					.getResultsByAuthMethod(
							authMethod);
		}

		model.addAttribute(
				"results",
				results);

		// =====================================================
		// 全体集計
		// =====================================================

		model.addAttribute(
				"totalExperimentCount",
				experimentResultService
				.getTotalExperimentCount());

		model.addAttribute(
				"totalAttemptCount",
				experimentResultService
				.getTotalAttemptCount());

		model.addAttribute(
				"totalAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCount());

		// =====================================================
		// 一段階認証
		// =====================================================

		model.addAttribute(
				"oneStageExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"one-stage"));

		model.addAttribute(
				"oneStageSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"one-stage"));

		model.addAttribute(
				"oneStageSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"one-stage"));

		model.addAttribute(
				"oneStageAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"one-stage"));

		model.addAttribute(
				"oneStageSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"one-stage"));

		model.addAttribute(
				"oneStageAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-stage"));

		// =====================================================
		// 二段階認証
		// =====================================================

		model.addAttribute(
				"twoStageExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"two-stage"));

		model.addAttribute(
				"twoStageSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"two-stage"));

		model.addAttribute(
				"twoStageSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"two-stage"));

		model.addAttribute(
				"twoStageAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"two-stage"));

		model.addAttribute(
				"twoStageSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"two-stage"));

		model.addAttribute(
				"twoStageAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"two-stage"));

		// =====================================================
		// 三段階認証
		// =====================================================

		model.addAttribute(
				"threeStageExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"three-stage"));

		model.addAttribute(
				"threeStageSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"three-stage"));

		model.addAttribute(
				"threeStageSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"three-stage"));

		model.addAttribute(
				"threeStageAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"three-stage"));

		model.addAttribute(
				"threeStageSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"three-stage"));

		model.addAttribute(
				"threeStageAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"three-stage"));

		// =====================================================
		// 一要素認証（Password）
		// =====================================================

		model.addAttribute(
				"oneFactorPasswordExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"one-factor-password"));

		model.addAttribute(
				"oneFactorPasswordSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"one-factor-password"));

		model.addAttribute(
				"oneFactorPasswordSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"one-factor-password"));

		model.addAttribute(
				"oneFactorPasswordAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"one-factor-password"));

		model.addAttribute(
				"oneFactorPasswordSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"one-factor-password"));

		model.addAttribute(
				"oneFactorPasswordAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-factor-password"));

		// =====================================================
		// 一要素認証（Email OTP）
		// =====================================================

		model.addAttribute(
				"oneFactorEmailOtpExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"one-factor-email-otp"));

		model.addAttribute(
				"oneFactorEmailOtpSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"one-factor-email-otp"));

		model.addAttribute(
				"oneFactorEmailOtpSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"one-factor-email-otp"));

		model.addAttribute(
				"oneFactorEmailOtpAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"one-factor-email-otp"));

		model.addAttribute(
				"oneFactorEmailOtpSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"one-factor-email-otp"));

		model.addAttribute(
				"oneFactorEmailOtpAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-factor-email-otp"));

		// =====================================================
		// 二要素認証（Password + Email OTP）
		// =====================================================

		model.addAttribute(
				"twoFactorPasswordEmailOtpExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"two-factor-password-email-otp"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"two-factor-password-email-otp"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"two-factor-password-email-otp"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"two-factor-password-email-otp"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"two-factor-password-email-otp"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"two-factor-password-email-otp"));

		return "results";
	}

	// =========================================================
	// 選択した結果を削除
	// =========================================================

	@PostMapping("/results/delete")
	public String deleteResults(
			@RequestParam(
					value = "ids",
					required = false)
			List<Long> ids) {

		if (ids != null
				&& !ids.isEmpty()) {

			experimentResultService
			.deleteResults(ids);
		}

		return "redirect:/results";
	}

	// =========================================================
	// 全結果削除
	// =========================================================

	@PostMapping("/results/clear")
	public String clearResults() {

		experimentResultService
		.clearResults();

		return "redirect:/results";
	}

	// =========================================================
	// Password試行回数
	// 0000～9999
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
	// Email OTP試行回数
	// 000000～999999
	// 1000000通り
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
	// 多段階認証の認証情報
	// =========================================================

	private String createMultiStageCredential(
			MultiStagePasswordBruteForceAttack
			.AttackResult result) {

		if (result.getStageCount() == 1) {

			return result.getPassword();

		} else if (result.getStageCount() == 2) {

			return result.getPassword()
					+ " → "
					+ result.getPassword2();

		} else if (result.getStageCount() == 3) {

			return result.getPassword()
					+ " → "
					+ result.getPassword2()
					+ " → "
					+ result.getPassword3();
		}

		return null;
	}

	// =========================================================
	// 多段階認証の構成
	// =========================================================

	private String createMultiStageConfiguration(
			MultiStagePasswordBruteForceAttack
			.AttackResult result) {

		if (result.getStageCount() == 1) {

			return "ID + Password";

		} else if (result.getStageCount() == 2) {

			return "ID + Password → Password2";

		} else if (result.getStageCount() == 3) {

			return "ID + Password → Password2 → Password3";
		}

		return null;
	}

	// =========================================================
	// 要素認証の認証情報
	// =========================================================

	private String createFactorCredential(
			FactorAuthenticationAttack
			.FactorAttackResult result) {

		String password =
				result.getPassword();

		String otp =
				result.getOtp();

		if (password != null
				&& otp != null) {

			return password
					+ " → "
					+ otp;
		}

		if (password != null) {

			return password;
		}

		if (otp != null) {

			return otp;
		}

		return null;
	}
}