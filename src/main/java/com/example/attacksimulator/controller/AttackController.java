package com.example.attacksimulator.controller;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
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
	// 一段階認証 / 二段階認証 / 三段階認証
	// 総当たり
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

			maxAttemptsPassword =
					clampPasswordAttempts(
							maxAttemptsPassword);

			maxAttemptsPassword2 =
					clampPasswordAttempts(
							maxAttemptsPassword2);

			maxAttemptsPassword3 =
					clampPasswordAttempts(
							maxAttemptsPassword3);

			// =================================================
			// 攻撃開始ログ
			// =================================================

			String attackStartTitle;

			if ("one-stage".equals(authMethod)) {

				attackStartTitle =
						"===== 一段階認証 総当たり攻撃開始 =====";

			} else if ("two-stage".equals(authMethod)) {

				attackStartTitle =
						"===== 二段階認証 総当たり攻撃開始 =====";

			} else if ("three-stage".equals(authMethod)) {

				attackStartTitle =
						"===== 三段階認証 総当たり攻撃開始 =====";

			} else {

				attackStartTitle =
						"===== 総当たり攻撃開始 =====";
			}

			System.out.println(
					attackStartTitle);

			System.out.println(
					"username = "
							+ username);

			if ("one-stage".equals(authMethod)) {

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptsPassword);

			} else if ("two-stage".equals(authMethod)) {

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptsPassword
								+ " → "
								+ maxAttemptsPassword2);

			} else if ("three-stage".equals(authMethod)) {

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptsPassword
								+ " → "
								+ maxAttemptsPassword2
								+ " → "
								+ maxAttemptsPassword3);
			}

			System.out.println(
					"========================================");

			MultiStagePasswordBruteForceAttack.AttackResult result;

			boolean realLoginSuccess =
					false;

			String maxAttemptCount;

			// =================================================
			// 一段階認証
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
			}

			// =================================================
			// 二段階認証
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
			}

			// =================================================
			// 三段階認証
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
			}

			else {

				throw new IllegalArgumentException(
						"不正な認証方式です。");
			}

			// =================================================
			// 試行制限による強制終了判定
			// =================================================

			boolean forceTerminated =
					result.isForceTerminated();

			// =================================================
			// 攻撃時間計算
			// =================================================

			long actualAttackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			long virtualWaitTimeMs =
					result.getVirtualWaitTimeMillis();

			long attackTimeMs =
					actualAttackTimeMs
					+ virtualWaitTimeMs;

			String credential =
					createMultiStageCredential(
							result);

			String configuration =
					createMultiStageConfiguration(
							result);

			// =================================================
			// 実験結果保存
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
			// 最終結果ログ
			// =================================================

			String resultTitle;

			if ("one-stage".equals(authMethod)) {

				resultTitle =
						"===== 一段階認証 総当たり攻撃結果 =====";

			} else if ("two-stage".equals(authMethod)) {

				resultTitle =
						"===== 二段階認証 総当たり攻撃結果 =====";

			} else {

				resultTitle =
						"===== 三段階認証 総当たり攻撃結果 =====";
			}

			System.out.println(
					resultTitle);

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"password = "
							+ credential);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"実攻撃試行回数 = "
							+ result.getTotalAttempts());

			System.out.println(
					"総当たり攻撃成功 = "
							+ result.isSuccess());

			System.out.println(
					"実ログイン成功 = "
							+ realLoginSuccess);

			System.out.println(
					"攻撃処理強制終了 = "
							+ forceTerminated);

			System.out.println(
					"実処理時間 = "
							+ actualAttackTimeMs
							+ " ms");

			System.out.println(
					"仮想待機時間 = "
							+ virtualWaitTimeMs
							+ " ms");

			System.out.println(
					"攻撃時間 = "
							+ attackTimeMs
							+ " ms");

			System.out.println(
					"========================================");

			// =================================================
			// 認証突破成功時
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
			// 結果画面へ渡す
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
					"maxAttemptCount",
					maxAttemptCount);

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			// 試行制限による強制終了かどうか
			redirectAttributes.addFlashAttribute(
					"forceTerminated",
					forceTerminated);

			// =================================================
			// 結果メッセージ
			// =================================================

			String message;

			if (forceTerminated) {

				message =
						"試行制限により攻撃処理を強制終了しました。";

			} else if (result.isSuccess()) {

				message =
						"認証突破に成功しました。";

			} else {

				message =
						"認証突破に失敗しました。";
			}

			redirectAttributes.addFlashAttribute(
					"message",
					message);

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					e.getMessage());

			return "redirect:/result";
		}
	}

	// =========================================================
	// 一段階認証
	// ランダム攻撃
	// =========================================================
	@PostMapping("/attack/random-stage")
	public String attackRandomStage(

			@RequestParam("username") String username,

			@RequestParam(
					value = "maxAttemptsPassword",
					required = false,
					defaultValue = "10000")
			int maxAttemptsPassword,

			RedirectAttributes redirectAttributes,

			Model model) {

		long startTime =
				System.nanoTime();

		final String authMethod =
				"one-stage-random";

		try {

			maxAttemptsPassword =
					clampPasswordAttempts(
							maxAttemptsPassword);

			// =================================================
			// 攻撃開始ログ
			// =================================================

			System.out.println(
					"===== 一段階認証 ランダム攻撃開始 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptsPassword);

			System.out.println(
					"試行制限 = 1000回ごと");

			System.out.println(
					"待機時間 = 1分 → 5分 → 10分 → 20分 → 30分 → 60分");

			System.out.println(
					"7000回失敗で攻撃処理を強制終了");

			System.out.println(
					"========================================");

			AttackService.RandomOneStageLoginResult
			randomResult =
					attackService
							.executeRandomOneStageWithLogin(
									username,
									maxAttemptsPassword);

			// =================================================
			// 実際にかかった処理時間
			//
			// Thread.sleep()などによる待機時間は含まれない
			// =================================================

			long actualAttackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			// =================================================
			// 仮想待機時間
			//
			// 実際には一切待機しない。
			//
			// 1000回失敗するごとに
			// 1分 → 5分 → 10分 → 20分 → 30分 → 60分
			// の仮想待機時間を攻撃時間へ加算する。
			//
			// 7000回失敗した場合は強制終了する。
			// =================================================

			long virtualWaitTimeMs =
					randomResult
							.getVirtualWaitTimeMillis();

			// =================================================
			// 実験上の攻撃時間
			//
			// 実処理時間
			// ＋
			// 仮想待機時間
			// =================================================

			long attackTimeMs =
					actualAttackTimeMs
							+ virtualWaitTimeMs;

			boolean attackSuccess =
					randomResult.isSuccess();

			boolean realLoginSuccess =
					randomResult.isLoginSuccess();

			/**
			 * 試行制限による強制終了
			 *
			 * 7000回失敗した場合 true
			 */
			boolean forceTerminated =
					randomResult.isForceTerminated();

			String password =
					randomResult.getPassword();

			int attemptCount =
					randomResult.getAttemptCount();

			// =================================================
			// 最終結果ログ
			// =================================================

			System.out.println(
					"===== 一段階ランダム攻撃結果 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"password = "
							+ password);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptsPassword);

			System.out.println(
					"実攻撃試行回数 = "
							+ attemptCount);

			System.out.println(
					"ランダム攻撃成功 = "
							+ attackSuccess);

			System.out.println(
					"実ログイン成功 = "
							+ realLoginSuccess);

			System.out.println(
					"攻撃処理強制終了 = "
							+ forceTerminated);

			System.out.println(
					"Final URL = "
							+ randomResult.getFinalUrl());

			System.out.println(
					"実処理時間 = "
							+ actualAttackTimeMs
							+ " ms");

			System.out.println(
					"仮想待機時間 = "
							+ virtualWaitTimeMs
							+ " ms");

			System.out.println(
					"攻撃時間 = "
							+ attackTimeMs
							+ " ms");

			System.out.println(
					"========================================");

			// =================================================
			// 実験結果保存
			//
			// 保存する攻撃時間は
			//
			// 実処理時間 + 仮想待機時間
			// =================================================

			experimentResultService.addResult(
					username,
					authMethod,
					"ID + Password",
					String.valueOf(
							maxAttemptsPassword),
					attemptCount,
					attackSuccess,
					password,
					attackTimeMs);

			// =================================================
			// 攻撃成功
			//
			// 強制終了の場合は成功にはならないため、
			// この条件には入らない。
			// =================================================

			if (attackSuccess
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						password);

				return "login-redirect";
			}

			// =================================================
			// 結果画面へ渡す
			// =================================================

			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					attemptCount);

			redirectAttributes.addFlashAttribute(
					"success",
					attackSuccess);

			redirectAttributes.addFlashAttribute(
					"password",
					password);

			redirectAttributes.addFlashAttribute(
					"password2",
					null);

			redirectAttributes.addFlashAttribute(
					"password3",
					null);

			redirectAttributes.addFlashAttribute(
					"otp",
					null);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			// =================================================
			// 強制終了状態
			// =================================================

			redirectAttributes.addFlashAttribute(
					"forceTerminated",
					forceTerminated);

			redirectAttributes.addFlashAttribute(
					"maxAttemptCount",
					String.valueOf(
							maxAttemptsPassword));

			// =================================================
			// 結果画面に渡す攻撃時間
			//
			// 仮想待機時間込み
			// =================================================

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			// =================================================
			// 結果メッセージ
			//
			// 強制終了を最優先する。
			// =================================================

			String message;

			if (forceTerminated) {

				message =
						"試行制限により一段階ランダム攻撃処理を強制終了しました。";

			} else if (attackSuccess) {

				message =
						"一段階ランダム攻撃の突破に成功しました。";

			} else {

				message =
						"一段階ランダム攻撃の突破に失敗しました。";
			}

			redirectAttributes.addFlashAttribute(
					"message",
					message);

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"ランダム攻撃中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
	}


	// =========================================================
	// 二段階認証
	// ランダム攻撃
	// =========================================================
	@PostMapping("/attack/random-two-stage")
	public String attackRandomTwoStage(
			@RequestParam("username") String username,

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

			RedirectAttributes redirectAttributes,
			Model model) {

		long startTime =
				System.nanoTime();

		final String authMethod =
				"two-stage-random";

		try {

			maxAttemptsPassword =
					clampPasswordAttempts(
							maxAttemptsPassword);

			maxAttemptsPassword2 =
					clampPasswordAttempts(
							maxAttemptsPassword2);

			String maxAttemptCount =
					maxAttemptsPassword
					+ " → "
					+ maxAttemptsPassword2;

			// =================================================
			// 攻撃開始ログ
			// =================================================

			System.out.println(
					"===== 二段階認証 ランダム攻撃開始 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"========================================");

			AttackService.RandomTwoStageLoginResult
			randomResult =
					attackService
					.executeRandomTwoStageWithLogin(
							username,
							maxAttemptsPassword,
							maxAttemptsPassword2);

			// =================================================
			// 実際にかかった攻撃処理時間
			// =================================================

			long actualAttackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			// =================================================
			// 実際には待っていない仮想待機時間
			// =================================================

			long virtualWaitTimeMs =
					randomResult
					.getVirtualWaitTimeMillis();

			// =================================================
			// 最終的な攻撃時間
			//
			// 実際の処理時間
			// ＋
			// 仮想待機時間
			// =================================================

			long attackTimeMs =
					actualAttackTimeMs
					+ virtualWaitTimeMs;

			// =================================================
			// 攻撃結果
			// =================================================

			boolean attackSuccess =
					randomResult.isSuccess();

			boolean realLoginSuccess =
					randomResult.isLoginSuccess();

			// =================================================
			// 強制終了状態
			// =================================================

			boolean forceTerminated =
					randomResult.isForceTerminated();

			String password =
					randomResult.getPassword();

			String password2 =
					randomResult.getPassword2();

			int passwordAttemptCount =
					randomResult
					.getPasswordAttemptCount();

			int password2AttemptCount =
					randomResult
					.getPassword2AttemptCount();

			int attemptCount =
					randomResult.getAttemptCount();

			String credential =
					createRandomTwoStageCredential(
							password,
							password2);

			// =================================================
			// 結果保存
			// =================================================

			experimentResultService.addResult(
					username,
					authMethod,
					"ID + Password → Password2",
					maxAttemptCount,
					attemptCount,
					attackSuccess,
					credential,
					attackTimeMs);

			// =================================================
			// 最終結果ログ
			// =================================================

			System.out.println(
					"===== 二段階ランダム攻撃結果 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"password = "
							+ credential);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"Password実攻撃試行回数 = "
							+ passwordAttemptCount);

			System.out.println(
					"Password2実攻撃試行回数 = "
							+ password2AttemptCount);

			System.out.println(
					"実攻撃試行回数 = "
							+ attemptCount);

			System.out.println(
					"ランダム攻撃成功 = "
							+ attackSuccess);

			System.out.println(
					"実ログイン成功 = "
							+ realLoginSuccess);

			System.out.println(
					"強制終了 = "
							+ forceTerminated);

			System.out.println(
					"実際の攻撃処理時間 = "
							+ actualAttackTimeMs
							+ " ms");

			System.out.println(
					"仮想待機時間 = "
							+ virtualWaitTimeMs
							+ " ms");

			System.out.println(
					"攻撃時間 = "
							+ attackTimeMs
							+ " ms");

			System.out.println(
					"========================================");

			// =================================================
			// 攻撃成功 ＆ 実ログイン成功
			//
			// 強制終了の場合は success=false なので
			// ここには入らない。
			// =================================================

			if (attackSuccess
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						password);

				model.addAttribute(
						"password2",
						password2);

				return "two-stage-login-redirect";
			}

			// =================================================
			// 結果画面へ渡す
			// =================================================

			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					attemptCount);

			redirectAttributes.addFlashAttribute(
					"success",
					attackSuccess);

			redirectAttributes.addFlashAttribute(
					"password",
					password);

			redirectAttributes.addFlashAttribute(
					"password2",
					password2);

			redirectAttributes.addFlashAttribute(
					"password3",
					null);

			redirectAttributes.addFlashAttribute(
					"otp",
					null);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			redirectAttributes.addFlashAttribute(
					"maxAttemptCount",
					maxAttemptCount);

			redirectAttributes.addFlashAttribute(
					"passwordAttemptCount",
					passwordAttemptCount);

			redirectAttributes.addFlashAttribute(
					"password2AttemptCount",
					password2AttemptCount);

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			// =================================================
			// 強制終了状態を結果画面へ渡す
			// =================================================

			redirectAttributes.addFlashAttribute(
					"forceTerminated",
					forceTerminated);

			// =================================================
			// メッセージ
			// =================================================

			String message;

			if (forceTerminated) {

				message =
						"試行制限により二段階認証（ランダム）"
						+ "の攻撃処理を強制終了しました。";

			} else if (attackSuccess) {

				message =
						"二段階認証（ランダム）の突破に成功しました。";

			} else {

				message =
						"二段階認証（ランダム）の突破に失敗しました。";
			}

			redirectAttributes.addFlashAttribute(
					"message",
					message);

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"二段階ランダム攻撃中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
	}


	// =========================================================
	// 三段階認証
	// ランダム攻撃
	// =========================================================

	@PostMapping("/attack/random-three-stage")

	public String attackRandomThreeStage(

			@RequestParam("username") String username,

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

		final String authMethod =
				"three-stage-random";

		try {

			maxAttemptsPassword =
					clampPasswordAttempts(
							maxAttemptsPassword);

			maxAttemptsPassword2 =
					clampPasswordAttempts(
							maxAttemptsPassword2);

			maxAttemptsPassword3 =
					clampPasswordAttempts(
							maxAttemptsPassword3);

			String maxAttemptCount =
					maxAttemptsPassword
					+ " → "
					+ maxAttemptsPassword2
					+ " → "
					+ maxAttemptsPassword3;

			// =================================================
			// 攻撃開始ログ
			// =================================================

			System.out.println(
					"===== 三段階認証 ランダム攻撃開始 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"========================================");

			AttackService.RandomThreeStageLoginResult
			randomResult =
					attackService
					.executeRandomThreeStageWithLogin(
							username,
							maxAttemptsPassword,
							maxAttemptsPassword2,
							maxAttemptsPassword3);

			// =================================================
			// 実際にかかった処理時間
			//
			// 実際には待機していないため、
			// BCrypt照合などの処理時間だけ。
			// =================================================

			long actualAttackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			// =================================================
			// 仮想待機時間
			//
			// Password
			// Password2
			// Password3
			//
			// 各段階で
			//
			// 1000回  → 1分
			// 2000回  → 5分
			// 3000回  → 10分
			// 4000回  → 20分
			// 5000回  → 30分
			// 6000回  → 60分
			// 7000回  → 強制終了
			//
			// 強制終了時の追加待機時間は0。
			// =================================================

			long virtualWaitTimeMs =
					randomResult
							.getVirtualWaitTimeMillis();

			// =================================================
			// 実験上の攻撃時間
			//
			// 実処理時間
			// ＋
			// 仮想待機時間
			// =================================================

			long attackTimeMs =
					actualAttackTimeMs
					+ virtualWaitTimeMs;

			boolean attackSuccess =
					randomResult.isSuccess();

			boolean realLoginSuccess =
					randomResult.isLoginSuccess();

			// =================================================
			// 試行制限による強制終了
			// =================================================

			boolean forceTerminated =
					randomResult.isForceTerminated();

			String password =
					randomResult.getPassword();

			String password2 =
					randomResult.getPassword2();

			String password3 =
					randomResult.getPassword3();

			int passwordAttemptCount =
					randomResult
					.getPasswordAttemptCount();

			int password2AttemptCount =
					randomResult
					.getPassword2AttemptCount();

			int password3AttemptCount =
					randomResult
					.getPassword3AttemptCount();

			int attemptCount =
					randomResult.getAttemptCount();

			String credential =
					createRandomThreeStageCredential(
							password,
							password2,
							password3);

			// =================================================
			// 実験結果保存
			//
			// 保存する攻撃時間は
			//
			// 実処理時間 + 仮想待機時間
			// =================================================

			experimentResultService.addResult(
					username,
					authMethod,
					"ID + Password → Password2 → Password3",
					maxAttemptCount,
					attemptCount,
					attackSuccess,
					credential,
					attackTimeMs);

			// =================================================
			// 最終結果ログ
			// =================================================

			System.out.println(
					"===== 三段階ランダム攻撃結果 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"password = "
							+ credential);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"Password試行回数 = "
							+ passwordAttemptCount);

			System.out.println(
					"Password2試行回数 = "
							+ password2AttemptCount);

			System.out.println(
					"Password3試行回数 = "
							+ password3AttemptCount);

			System.out.println(
					"実攻撃試行回数 = "
							+ attemptCount);

			System.out.println(
					"ランダム攻撃成功 = "
							+ attackSuccess);

			System.out.println(
					"実ログイン成功 = "
							+ realLoginSuccess);

			System.out.println(
					"強制終了 = "
							+ forceTerminated);

			System.out.println(
					"実処理時間 = "
							+ actualAttackTimeMs
							+ " ms");

			System.out.println(
					"仮想待機時間 = "
							+ virtualWaitTimeMs
							+ " ms");

			System.out.println(
					"攻撃時間 = "
							+ attackTimeMs
							+ " ms");

			System.out.println(
					"========================================");

			// =================================================
			// 攻撃成功
			//
			// 強制終了の場合は success=false なので
			// ここには入らない。
			// =================================================

			if (attackSuccess
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						password);

				model.addAttribute(
						"password2",
						password2);

				model.addAttribute(
						"password3",
						password3);

				return "three-stage-login-redirect";
			}

			// =================================================
			// 結果画面へ渡す
			// =================================================

			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					attemptCount);

			redirectAttributes.addFlashAttribute(
					"success",
					attackSuccess);

			redirectAttributes.addFlashAttribute(
					"password",
					password);

			redirectAttributes.addFlashAttribute(
					"password2",
					password2);

			redirectAttributes.addFlashAttribute(
					"password3",
					password3);

			redirectAttributes.addFlashAttribute(
					"otp",
					null);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			redirectAttributes.addFlashAttribute(
					"maxAttemptCount",
					maxAttemptCount);

			redirectAttributes.addFlashAttribute(
					"passwordAttemptCount",
					passwordAttemptCount);

			redirectAttributes.addFlashAttribute(
					"password2AttemptCount",
					password2AttemptCount);

			redirectAttributes.addFlashAttribute(
					"password3AttemptCount",
					password3AttemptCount);

			// =================================================
			// 強制終了フラグ
			// =================================================

			redirectAttributes.addFlashAttribute(
					"forceTerminated",
					forceTerminated);

			// =================================================
			// 仮想待機時間込みの攻撃時間
			// =================================================

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			// =================================================
			// 結果メッセージ
			//
			// 強制終了を最優先する。
			// =================================================

			String message;

			if (forceTerminated) {

				message =
						"試行制限により三段階認証（ランダム）攻撃処理を強制終了しました。";

			} else if (attackSuccess) {

				message =
						"三段階認証（ランダム）の突破に成功しました。";

			} else {

				message =
						"三段階認証（ランダム）の突破に失敗しました。";
			}

			redirectAttributes.addFlashAttribute(
					"message",
					message);

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"三段階ランダム攻撃中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
	}

	// =========================================================
	// 一要素認証
	// Email OTP
	// ランダム攻撃
	// =========================================================
	@PostMapping("/attack/random-email-otp")
	public String attackRandomEmailOtp(

			@RequestParam("username") String username,

			@RequestParam(
					value = "maxAttempts",
					required = false,
					defaultValue = "1000000")
			int maxAttempts,

			RedirectAttributes redirectAttributes) {

		long startTime =
				System.nanoTime();

		final String authMethod =
				"one-factor-email-otp-random";

		try {

			maxAttempts =
					clampOtpAttempts(
							maxAttempts);

			// =====================================================
			// 攻撃開始ログ
			// =====================================================
			System.out.println(
					"===== 一要素 Email OTP ランダム攻撃開始 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"最大試行回数 = "
							+ maxAttempts);

			System.out.println(
					"========================================");

			FactorAuthenticationAttack.FactorAttackResult randomResult =
					attackService.executeRandomOneFactorEmailOtp(
							username,
							maxAttempts);

			long attackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			boolean attackSuccess =
					randomResult.isSuccess();

			boolean realLoginSuccess =
					randomResult.isLoginSuccess();

			String otp =
					randomResult.getOtp();

			int attemptCount =
					randomResult.getAttemptCount();

			String finalUrl =
					randomResult.getFinalUrl();

			// =====================================================
			// 実験結果保存
			// =====================================================
			experimentResultService.addResult(
					username,
					authMethod,
					"ID + Email OTP",
					String.valueOf(maxAttempts),
					attemptCount,
					attackSuccess,
					otp,
					attackTimeMs);

			// =====================================================
			// 最終結果ログ
			// =====================================================
			System.out.println(
					"===== 一要素 Email OTP ランダム攻撃結果 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"otp = "
							+ otp);

			System.out.println(
					"最大試行回数 = "
							+ maxAttempts);

			System.out.println(
					"実攻撃試行回数 = "
							+ attemptCount);

			System.out.println(
					"ランダム攻撃成功 = "
							+ attackSuccess);

			System.out.println(
					"実ログイン成功 = "
							+ realLoginSuccess);

			System.out.println(
					"Final URL = "
							+ finalUrl);

			System.out.println(
					"攻撃時間 = "
							+ attackTimeMs
							+ " ms");

			System.out.println(
					"========================================");

			// =====================================================
			// 実際のログイン成功
			// =====================================================
			if (attackSuccess
					&& realLoginSuccess
					&& finalUrl != null
					&& !finalUrl.isBlank()) {

				return "redirect:" + finalUrl;
			}

			// =====================================================
			// 結果画面
			// =====================================================
			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					attemptCount);

			redirectAttributes.addFlashAttribute(
					"success",
					attackSuccess);

			redirectAttributes.addFlashAttribute(
					"password",
					null);

			redirectAttributes.addFlashAttribute(
					"password2",
					null);

			redirectAttributes.addFlashAttribute(
					"password3",
					null);

			redirectAttributes.addFlashAttribute(
					"otp",
					otp);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			redirectAttributes.addFlashAttribute(
					"maxAttemptCount",
					String.valueOf(maxAttempts));

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			redirectAttributes.addFlashAttribute(
					"message",
					attackSuccess
					? "一要素 Email OTP（ランダム）の突破に成功しました。"
							: "一要素 Email OTP（ランダム）の突破に失敗しました。");

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"Email OTPランダム攻撃中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
	}


	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// ランダム攻撃
	// =========================================================
	@PostMapping("/attack/random-two-factor")
	public String attackRandomTwoFactor(

			@RequestParam("username") String username,

			@RequestParam(
					value = "maxAttemptsPassword",
					required = false,
					defaultValue = "10000")
			int maxAttemptsPassword,

			@RequestParam(
					value = "maxAttemptsOtp",
					required = false,
					defaultValue = "1000000")
			int maxAttemptsOtp,

			RedirectAttributes redirectAttributes) {

		long startTime =
				System.nanoTime();

		try {

			// =====================================================
			// 最大試行回数
			// =====================================================
			maxAttemptsPassword =
					clampPasswordAttempts(
							maxAttemptsPassword);

			maxAttemptsOtp =
					clampOtpAttempts(
							maxAttemptsOtp);

			String maxAttemptCount =
					maxAttemptsPassword
					+ " → "
					+ maxAttemptsOtp;

			// =====================================================
			// 攻撃開始ログ
			// =====================================================
			System.out.println(
					"===== 二要素認証 ランダム攻撃開始 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"========================================");

			// =====================================================
			// 二要素ランダム攻撃実行
			// =====================================================
			FactorAuthenticationAttack.FactorAttackResult result =
					attackService
					.executeRandomTwoFactorPasswordEmailOtp(
							username,
							maxAttemptsPassword,
							maxAttemptsOtp);

			long attackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			// =====================================================
			// 結果
			// =====================================================
			boolean attackSuccess =
					result.isSuccess();

			boolean realLoginSuccess =
					result.isLoginSuccess();

			String password =
					result.getPassword();

			String otp =
					result.getOtp();

			int totalAttemptCount =
					result.getAttemptCount();

			String finalUrl =
					result.getFinalUrl();

			// =====================================================
			// 認証方式
			// =====================================================
			String authMethod =
					"two-factor-password-email-otp-random";

			String configuration =
					"ID + Random Password → Random Email OTP";

			// =====================================================
			// 成功した認証情報
			// =====================================================
			String credential = null;

			if (password != null
					&& !password.isBlank()
					&& otp != null
					&& !otp.isBlank()) {

				credential =
						password
						+ " → "
						+ otp;
			}

			// =====================================================
			// 実験結果保存
			// =====================================================
			experimentResultService.addResult(
					username,
					authMethod,
					configuration,
					maxAttemptCount,
					totalAttemptCount,
					attackSuccess,
					credential,
					attackTimeMs);

			// =====================================================
			// 最終結果ログ
			// =====================================================
			System.out.println(
					"===== 二要素認証ランダム攻撃結果 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"password = "
							+ credential);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"実攻撃試行回数 = "
							+ totalAttemptCount);

			System.out.println(
					"ランダム攻撃成功 = "
							+ attackSuccess);

			System.out.println(
					"実ログイン成功 = "
							+ realLoginSuccess);

			System.out.println(
					"Final URL = "
							+ finalUrl);

			System.out.println(
					"攻撃時間 = "
							+ attackTimeMs
							+ " ms");

			System.out.println(
					"========================================");

			// =====================================================
			// 実際のログイン成功
			// =====================================================
			if (attackSuccess
					&& realLoginSuccess
					&& finalUrl != null
					&& !finalUrl.isBlank()) {

				return "redirect:" + finalUrl;
			}

			// =====================================================
			// 結果画面
			// =====================================================
			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					totalAttemptCount);

			redirectAttributes.addFlashAttribute(
					"success",
					attackSuccess);

			redirectAttributes.addFlashAttribute(
					"password",
					password);

			redirectAttributes.addFlashAttribute(
					"password2",
					null);

			redirectAttributes.addFlashAttribute(
					"password3",
					null);

			redirectAttributes.addFlashAttribute(
					"otp",
					otp);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			redirectAttributes.addFlashAttribute(
					"maxAttemptCount",
					maxAttemptCount);

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			redirectAttributes.addFlashAttribute(
					"message",
					attackSuccess
					? "二要素認証（ランダム）の突破に成功しました。"
							: "二要素認証（ランダム）の突破に失敗しました。");

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"二要素認証（ランダム攻撃）中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
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

			// =====================================================
			// 一要素 Password
			// 総当たり攻撃
			// =====================================================
			if ("one-factor-password".equals(authMethod)) {

				maxAttemptsPassword =
						clampPasswordAttempts(
								maxAttemptsPassword);

				// =================================================
				// 攻撃開始ログ
				// =================================================
				System.out.println(
						"===== 一要素 Password 総当たり攻撃開始 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptsPassword);

				System.out.println(
						"========================================");

				FactorAuthenticationAttack.FactorAttackResult passwordResult =
						attackService.executeOneFactorPassword(
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
								passwordResult);

				boolean attackSuccess =
						passwordResult.isSuccess();

				boolean realLoginSuccess =
						false;

				String finalUrl = null;

				// =================================================
				// 実際のNewAuthLabログイン
				// =================================================
				if (attackSuccess) {

					NewAuthLabLoginClient.LoginResult loginResult =
							newAuthLabLoginClient.loginOneStage(
									username,
									passwordResult.getPassword());

					realLoginSuccess =
							loginResult.isSuccess();

					finalUrl =
							loginResult.getFinalUrl();
				}

				// =================================================
				// 実験結果保存
				// =================================================
				experimentResultService.addResult(
						username,
						passwordResult.getAuthMethod(),
						passwordResult
						.getAuthenticationConfiguration(),
						maxAttemptCount,
						passwordResult.getAttemptCount(),
						attackSuccess,
						credential,
						attackTimeMs);

				// =================================================
				// 最終結果ログ
				// =================================================
				System.out.println(
						"===== 一要素 Password 総当たり攻撃結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ passwordResult.getPassword());

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"実攻撃試行回数 = "
								+ passwordResult.getAttemptCount());

				System.out.println(
						"総当たり攻撃成功 = "
								+ attackSuccess);

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"Final URL = "
								+ finalUrl);

				System.out.println(
						"攻撃時間 = "
								+ attackTimeMs
								+ " ms");

				System.out.println(
						"========================================");

				// =================================================
				// ログイン成功
				// =================================================
				if (attackSuccess
						&& realLoginSuccess) {

					model.addAttribute(
							"username",
							username);

					model.addAttribute(
							"password",
							passwordResult.getPassword());

					return "login-redirect";
				}

				// =================================================
				// 結果画面
				// =================================================
				redirectAttributes.addFlashAttribute(
						"authMethod",
						authMethod);

				redirectAttributes.addFlashAttribute(
						"attemptCount",
						passwordResult.getAttemptCount());

				redirectAttributes.addFlashAttribute(
						"success",
						attackSuccess);

				redirectAttributes.addFlashAttribute(
						"password",
						passwordResult.getPassword());

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
						"maxAttemptCount",
						maxAttemptCount);

				redirectAttributes.addFlashAttribute(
						"attackTimeMs",
						attackTimeMs);

				redirectAttributes.addFlashAttribute(
						"message",
						attackSuccess
						? "認証突破に成功しました。"
								: "認証突破に失敗しました。");

				return "redirect:/result";
			}


			// =====================================================
			// 一要素 Password
			// ランダム攻撃
			// =====================================================
			if ("one-factor-password-random"
					.equals(authMethod)) {

				maxAttemptsPassword =
						clampPasswordAttempts(
								maxAttemptsPassword);

				// =================================================
				// 攻撃開始ログ
				// =================================================
				System.out.println(
						"===== 一要素 Password ランダム攻撃開始 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptsPassword);

				System.out.println(
						"========================================");

				FactorAuthenticationAttack.FactorAttackResult randomPasswordResult =
						attackService
						.executeOneFactorRandomPassword(
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
								randomPasswordResult);

				boolean attackSuccess =
						randomPasswordResult.isSuccess();

				boolean realLoginSuccess =
						false;

				String finalUrl = null;

				// =================================================
				// 実際のNewAuthLabログイン
				// =================================================
				if (attackSuccess) {

					NewAuthLabLoginClient.LoginResult loginResult =
							newAuthLabLoginClient.loginOneStage(
									username,
									randomPasswordResult.getPassword());

					realLoginSuccess =
							loginResult.isSuccess();

					finalUrl =
							loginResult.getFinalUrl();
				}

				// =================================================
				// 実験結果保存
				// =================================================
				experimentResultService.addResult(
						username,
						randomPasswordResult.getAuthMethod(),
						randomPasswordResult
						.getAuthenticationConfiguration(),
						maxAttemptCount,
						randomPasswordResult.getAttemptCount(),
						attackSuccess,
						credential,
						attackTimeMs);

				// =================================================
				// 最終結果ログ
				// =================================================
				System.out.println(
						"===== 一要素 Password ランダム攻撃結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ randomPasswordResult.getPassword());

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"実攻撃試行回数 = "
								+ randomPasswordResult.getAttemptCount());

				System.out.println(
						"ランダム攻撃成功 = "
								+ attackSuccess);

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"Final URL = "
								+ finalUrl);

				System.out.println(
						"攻撃時間 = "
								+ attackTimeMs
								+ " ms");

				System.out.println(
						"========================================");

				// =================================================
				// ログイン成功
				// =================================================
				if (attackSuccess
						&& realLoginSuccess) {

					model.addAttribute(
							"username",
							username);

					model.addAttribute(
							"password",
							randomPasswordResult
							.getPassword());

					return "login-redirect";
				}

				// =================================================
				// 結果画面
				// =================================================
				redirectAttributes.addFlashAttribute(
						"authMethod",
						authMethod);

				redirectAttributes.addFlashAttribute(
						"attemptCount",
						randomPasswordResult
						.getAttemptCount());

				redirectAttributes.addFlashAttribute(
						"success",
						attackSuccess);

				redirectAttributes.addFlashAttribute(
						"password",
						randomPasswordResult
						.getPassword());

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
						"maxAttemptCount",
						maxAttemptCount);

				redirectAttributes.addFlashAttribute(
						"attackTimeMs",
						attackTimeMs);

				redirectAttributes.addFlashAttribute(
						"message",
						attackSuccess
						? "一要素Password（ランダム）の認証突破に成功しました。"
								: "一要素Password（ランダム）の認証突破に失敗しました。");

				return "redirect:/result";
			}


			// =====================================================
			// 一要素 Email OTP
			// 総当たり攻撃
			// =====================================================
			if ("one-factor-email-otp"
					.equals(authMethod)) {

				maxAttempts =
						clampOtpAttempts(
								maxAttempts);

				// =================================================
				// 攻撃開始ログ
				// =================================================
				System.out.println(
						"===== 一要素 Email OTP 総当たり攻撃開始 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"最大試行回数 = "
								+ maxAttempts);

				System.out.println(
						"========================================");

				FactorAuthenticationAttack.FactorAttackResult emailOtpResult =
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

				boolean attackSuccess =
						emailOtpResult.isSuccess();

				boolean realLoginSuccess =
						emailOtpResult.isLoginSuccess();

				String finalUrl =
						emailOtpResult.getFinalUrl();

				// =================================================
				// 実験結果保存
				// =================================================
				experimentResultService.addResult(
						username,
						emailOtpResult.getAuthMethod(),
						emailOtpResult
						.getAuthenticationConfiguration(),
						maxAttemptCount,
						emailOtpResult.getAttemptCount(),
						attackSuccess,
						credential,
						attackTimeMs);

				// =================================================
				// 最終結果ログ
				// =================================================
				System.out.println(
						"===== 一要素 Email OTP 総当たり攻撃結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"otp = "
								+ emailOtpResult.getOtp());

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"実攻撃試行回数 = "
								+ emailOtpResult.getAttemptCount());

				System.out.println(
						"総当たり攻撃成功 = "
								+ attackSuccess);

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"Final URL = "
								+ finalUrl);

				System.out.println(
						"攻撃時間 = "
								+ attackTimeMs
								+ " ms");

				System.out.println(
						"========================================");

				// =================================================
				// ログイン成功
				// =================================================
				if (attackSuccess
						&& realLoginSuccess
						&& finalUrl != null
						&& !finalUrl.isBlank()) {

					return "redirect:" + finalUrl;
				}

				// =================================================
				// 結果画面
				// =================================================
				redirectAttributes.addFlashAttribute(
						"authMethod",
						authMethod);

				redirectAttributes.addFlashAttribute(
						"attemptCount",
						emailOtpResult.getAttemptCount());

				redirectAttributes.addFlashAttribute(
						"success",
						attackSuccess);

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
						realLoginSuccess);

				redirectAttributes.addFlashAttribute(
						"maxAttemptCount",
						maxAttemptCount);

				redirectAttributes.addFlashAttribute(
						"attackTimeMs",
						attackTimeMs);

				redirectAttributes.addFlashAttribute(
						"message",
						attackSuccess
						? "Email OTPの認証突破に成功しました。"
								: "Email OTPの認証突破に失敗しました。");

				return "redirect:/result";
			}


			// =====================================================
			// 二要素認証
			// Password → Email OTP
			// 総当たり攻撃
			// =====================================================
			if ("two-factor-password-email-otp"
					.equals(authMethod)) {

				maxAttemptsPassword =
						clampPasswordAttempts(
								maxAttemptsPassword);

				maxAttempts =
						clampOtpAttempts(
								maxAttempts);

				// =================================================
				// 攻撃開始ログ
				// =================================================
				System.out.println(
						"===== 二要素認証 総当たり攻撃開始 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptsPassword
								+ " → "
								+ maxAttempts);

				System.out.println(
						"========================================");

				FactorAuthenticationAttack.FactorAttackResult twoFactorResult =
						attackService
						.executeTwoFactorPasswordEmailOtp(
								username,
								maxAttemptsPassword,
								maxAttempts);

				long attackTimeMs =
						(System.nanoTime() - startTime)
						/ 1_000_000;

				String maxAttemptCount =
						maxAttemptsPassword
						+ " → "
						+ maxAttempts;

				String credential =
						createFactorCredential(
								twoFactorResult);

				boolean attackSuccess =
						twoFactorResult.isSuccess();

				boolean realLoginSuccess =
						twoFactorResult.isLoginSuccess();

				String finalUrl =
						twoFactorResult.getFinalUrl();

				// =================================================
				// 実験結果保存
				// =================================================
				experimentResultService.addResult(
						username,
						twoFactorResult.getAuthMethod(),
						twoFactorResult
						.getAuthenticationConfiguration(),
						maxAttemptCount,
						twoFactorResult.getAttemptCount(),
						attackSuccess,
						credential,
						attackTimeMs);

				// =================================================
				// 最終結果ログ
				// =================================================
				System.out.println(
						"===== 二要素認証 総当たり攻撃結果 =====");

				System.out.println(
						"username = "
								+ username);

				System.out.println(
						"password = "
								+ credential);

				System.out.println(
						"最大試行回数 = "
								+ maxAttemptCount);

				System.out.println(
						"実攻撃試行回数 = "
								+ twoFactorResult.getAttemptCount());

				System.out.println(
						"総当たり攻撃成功 = "
								+ attackSuccess);

				System.out.println(
						"実ログイン成功 = "
								+ realLoginSuccess);

				System.out.println(
						"Final URL = "
								+ finalUrl);

				System.out.println(
						"攻撃時間 = "
								+ attackTimeMs
								+ " ms");

				System.out.println(
						"========================================");

				// =================================================
				// ログイン成功
				// =================================================
				if (attackSuccess
						&& realLoginSuccess
						&& finalUrl != null
						&& !finalUrl.isBlank()) {

					return "redirect:" + finalUrl;
				}

				// =================================================
				// 結果画面
				// =================================================
				redirectAttributes.addFlashAttribute(
						"authMethod",
						authMethod);

				redirectAttributes.addFlashAttribute(
						"attemptCount",
						twoFactorResult.getAttemptCount());

				redirectAttributes.addFlashAttribute(
						"success",
						attackSuccess);

				redirectAttributes.addFlashAttribute(
						"password",
						twoFactorResult.getPassword());

				redirectAttributes.addFlashAttribute(
						"otp",
						twoFactorResult.getOtp());

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
						"attackTimeMs",
						attackTimeMs);

				redirectAttributes.addFlashAttribute(
						"message",
						attackSuccess
						? "二要素認証の突破に成功しました。"
								: "二要素認証の突破に失敗しました。");

				return "redirect:/result";
			}


			// =====================================================
			// 不正な認証方式
			// =====================================================
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
	// 辞書件数制限
	// =========================================================

	private int clampDictionaryEntries(
			int maxEntries) {

		if (maxEntries < 1) {

			return 1;
		}

		if (maxEntries > 100) {

			return 100;
		}

		return maxEntries;
	}


	// =========================================================
	// 辞書攻撃
	// 一段階認証のみ
	// =========================================================
	@PostMapping("/attack/dictionary-stage")
	public String attackDictionaryStage(

			@RequestParam("username")
			String username,

			@RequestParam(
					value = "authMethod",
					defaultValue = "one-stage-dictionary")
			String authMethod,

			@RequestParam(
					value = "maxAttemptsPassword",
					required = false,
					defaultValue = "100")
			int maxAttemptsPassword,

			RedirectAttributes redirectAttributes,

			Model model) {

		long startTime =
				System.nanoTime();

		try {

			// =====================================================
			// 一段階辞書攻撃以外は拒否
			// =====================================================

			if (!"one-stage-dictionary".equals(authMethod)) {

				throw new IllegalArgumentException(
						"辞書攻撃は一段階認証のみ対応しています。");
			}

			// =====================================================
			// 最大辞書件数を制限
			// =====================================================

			maxAttemptsPassword =
					clampDictionaryEntries(
							maxAttemptsPassword);

			// =====================================================
			// 辞書攻撃開始ログ
			// =====================================================

			System.out.println(
					"========================================");

			System.out.println(
					"一段階辞書攻撃開始");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptsPassword);

			System.out.println(
					"試行制限 = 10回失敗ごとに適用");
			System.out.println(
					"制限時間 = 1分 → 5分 → 10分 → 20分 → 30分 → 60分");
			System.out.println(
					"70回失敗で攻撃処理を強制終了");

			System.out.println(
					"========================================");

			// =====================================================
			// 辞書攻撃実行
			// =====================================================

			AttackService.DictionaryLoginResult result =
					attackService.executeDictionaryWithLogin(
							username,
							authMethod,
							maxAttemptsPassword,
							0,
							0);

			// =====================================================
			// 実処理時間
			// =====================================================

			long actualAttackTimeMs =
					(System.nanoTime() - startTime)
					/ 1_000_000;

			// =====================================================
			// 仮想待機時間
			// =====================================================

			long virtualWaitTimeMs =
					result.getVirtualWaitTimeMillis();

			// =====================================================
			// 攻撃時間
			//
			// 実処理時間 + 仮想待機時間
			// =====================================================

			long attackTimeMs =
					actualAttackTimeMs
					+ virtualWaitTimeMs;

			// =====================================================
			// 攻撃結果
			// =====================================================

			boolean attackSuccess =
					result.isSuccess();

			boolean realLoginSuccess =
					result.isLoginSuccess();

			boolean forceTerminated =
					result.isForceTerminated();

			String password =
					result.getPassword();

			int attemptCount =
					result.getAttemptCount();

			// =====================================================
			// 実ログイン成功判定
			// =====================================================

			String finalUrl =
					result.getFinalUrl();

			realLoginSuccess =
					isDictionaryLoginSuccess(
							authMethod,
							finalUrl);

			if (!realLoginSuccess) {

				attackSuccess = false;
			}

			// =====================================================
			// 実験結果保存
			// =====================================================

			String configuration =
					"ID + Password";

			String maxAttemptCount =
					String.valueOf(
							maxAttemptsPassword);

			String credential =
					createDictionaryCredential(
							password,
							null,
							null);

			experimentResultService.addResult(
					username,
					authMethod,
					configuration,
					maxAttemptCount,
					attemptCount,
					attackSuccess,
					credential,
					attackTimeMs);

			// =====================================================
			// 最終結果ログ
			// =====================================================

			System.out.println(
					"===== 一段階辞書攻撃結果 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"password = "
							+ password);

			System.out.println(
					"最大試行回数 = "
							+ maxAttemptCount);

			System.out.println(
					"実攻撃試行回数 = "
							+ attemptCount);

			System.out.println(
					"辞書攻撃成功 = "
							+ attackSuccess);

			System.out.println(
					"実ログイン成功 = "
							+ realLoginSuccess);

			System.out.println(
					"Final URL = "
							+ finalUrl);

			System.out.println(
					"実処理時間 = "
							+ actualAttackTimeMs
							+ " ms");

			System.out.println(
					"仮想待機時間 = "
							+ virtualWaitTimeMs
							+ " ms");

			System.out.println(
					"攻撃時間 = "
							+ attackTimeMs
							+ " ms");

			System.out.println(
					"========================================");

			// =====================================================
			// 実ログイン成功
			// =====================================================

			if (attackSuccess
					&& realLoginSuccess) {

				model.addAttribute(
						"username",
						username);

				model.addAttribute(
						"password",
						password);

				return "login-redirect";
			}

			// =====================================================
			// 結果画面
			// =====================================================

			redirectAttributes.addFlashAttribute(
					"authMethod",
					authMethod);

			redirectAttributes.addFlashAttribute(
					"attemptCount",
					attemptCount);

			redirectAttributes.addFlashAttribute(
					"success",
					attackSuccess);

			redirectAttributes.addFlashAttribute(
					"password",
					password);

			redirectAttributes.addFlashAttribute(
					"password2",
					null);

			redirectAttributes.addFlashAttribute(
					"password3",
					null);

			redirectAttributes.addFlashAttribute(
					"otp",
					null);

			redirectAttributes.addFlashAttribute(
					"realLoginSuccess",
					realLoginSuccess);

			redirectAttributes.addFlashAttribute(
					"maxAttemptCount",
					maxAttemptCount);

			redirectAttributes.addFlashAttribute(
					"attackTimeMs",
					attackTimeMs);

			redirectAttributes.addFlashAttribute(
					"actualAttackTimeMs",
					actualAttackTimeMs);

			redirectAttributes.addFlashAttribute(
					"virtualWaitTimeMs",
					virtualWaitTimeMs);
			
			redirectAttributes.addFlashAttribute(
					"forceTerminated",
					forceTerminated);

			String message;

			if (forceTerminated) {

				message =
						"試行制限により辞書攻撃の処理を強制終了しました。";

			} else if (attackSuccess) {

				message =
						"辞書攻撃による認証突破に成功しました。";

			} else {

				message =
						"辞書攻撃による認証突破に失敗しました。";
			}

			redirectAttributes.addFlashAttribute(
					"message",
					message);

			return "redirect:/result";

		} catch (Exception e) {

			e.printStackTrace();

			redirectAttributes.addFlashAttribute(
					"error",
					"辞書攻撃中にエラーが発生しました: "
							+ e.getMessage());

			return "redirect:/result";
		}
	}

	// =========================================================
	// 辞書攻撃方式判定
	// =========================================================

	private boolean isDictionaryAuthMethod(
			String authMethod) {

		return "one-stage-dictionary"
				.equals(authMethod);
	}

	// =========================================================
	// 辞書攻撃
	// 実ログイン成功判定
	// =========================================================

	private boolean isDictionaryLoginSuccess(
			String authMethod,
			String finalUrl) {

		if (!"one-stage-dictionary".equals(authMethod)
				|| finalUrl == null
				|| finalUrl.isBlank()) {

			return false;
		}

		try {

			URI uri = URI.create(finalUrl);

			String path = uri.getPath();

			return "/".equals(path)
					|| "/home".equals(path);

		} catch (Exception e) {

			return false;
		}
	}

	// =========================================================
	// 辞書攻撃の認証情報
	// 一段階認証のみ
	// =========================================================

	private String createDictionaryCredential(
			String password,
			String password2,
			String password3) {

		if (password == null || password.isBlank()) {
			return null;
		}

		return password;
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

			if ("one-factor-email-otp"
					.equals(authMethod)
					|| "one-factor-email-otp-random"
					.equals(authMethod)) {

				model.addAttribute(
						"otp",
						credential);

			}

			else {

				String[] credentials =
						credential.split(
								" → ");

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
	public String results(Model model) {

		List<ExperimentResult> results =
				experimentResultService
				.getAllResults();

		model.addAttribute(
				"results",
				results);

		Map<Long, String> formattedAttackTimeMap =
				results.stream()
				.collect(
						Collectors.toMap(
								ExperimentResult::getId,
								result ->
								experimentResultService
								.formatDuration(
										result.getAttackTimeMs()),
								(oldValue, newValue)
								-> newValue,
								LinkedHashMap::new));

		model.addAttribute(
				"formattedAttackTimeMap",
				formattedAttackTimeMap);

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
				"oneStageSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"one-stage"));

		model.addAttribute(
				"oneStageAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-stage"));

		model.addAttribute(
				"oneStageAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
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
				"twoStageSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"two-stage"));

		model.addAttribute(
				"twoStageAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"two-stage"));

		model.addAttribute(
				"twoStageAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
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
				"threeStageSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"three-stage"));

		model.addAttribute(
				"threeStageAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"three-stage"));

		model.addAttribute(
				"threeStageAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"three-stage"));

		// =====================================================
		// 一要素認証 Password
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
				"oneFactorPasswordSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"one-factor-password"));

		model.addAttribute(
				"oneFactorPasswordAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-factor-password"));

		model.addAttribute(
				"oneFactorPasswordAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"one-factor-password"));

		// =====================================================
		// 一要素認証 Password ランダム
		// =====================================================
		model.addAttribute(
				"oneFactorPasswordRandomExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"one-factor-password-random"));

		model.addAttribute(
				"oneFactorPasswordRandomSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"one-factor-password-random"));

		model.addAttribute(
				"oneFactorPasswordRandomSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"one-factor-password-random"));

		model.addAttribute(
				"oneFactorPasswordRandomAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"one-factor-password-random"));

		model.addAttribute(
				"oneFactorPasswordRandomSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"one-factor-password-random"));

		model.addAttribute(
				"oneFactorPasswordRandomSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"one-factor-password-random"));

		model.addAttribute(
				"oneFactorPasswordRandomAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-factor-password-random"));

		model.addAttribute(
				"oneFactorPasswordRandomAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"one-factor-password-random"));

		// =====================================================
		// 一要素認証 Email OTP
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
				"oneFactorEmailOtpSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"one-factor-email-otp"));

		model.addAttribute(
				"oneFactorEmailOtpAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-factor-email-otp"));

		model.addAttribute(
				"oneFactorEmailOtpAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"one-factor-email-otp"));

		// =====================================================
		// 一要素認証 Email OTP ランダム
		// =====================================================

		model.addAttribute(
				"oneFactorEmailOtpRandomExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"one-factor-email-otp-random"));

		model.addAttribute(
				"oneFactorEmailOtpRandomSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"one-factor-email-otp-random"));

		model.addAttribute(
				"oneFactorEmailOtpRandomSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"one-factor-email-otp-random"));

		model.addAttribute(
				"oneFactorEmailOtpRandomAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"one-factor-email-otp-random"));

		model.addAttribute(
				"oneFactorEmailOtpRandomSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"one-factor-email-otp-random"));

		model.addAttribute(
				"oneFactorEmailOtpRandomSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"one-factor-email-otp-random"));

		model.addAttribute(
				"oneFactorEmailOtpRandomAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-factor-email-otp-random"));

		model.addAttribute(
				"oneFactorEmailOtpRandomAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"one-factor-email-otp-random"));

		// =====================================================
		// 二要素認証 Password + Email OTP
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
				"twoFactorPasswordEmailOtpSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"two-factor-password-email-otp"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"two-factor-password-email-otp"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"two-factor-password-email-otp"));

		// =====================================================
		// 一段階認証 ランダム
		// =====================================================

		model.addAttribute(
				"oneStageRandomExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"one-stage-random"));

		model.addAttribute(
				"oneStageRandomSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"one-stage-random"));

		model.addAttribute(
				"oneStageRandomSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"one-stage-random"));

		model.addAttribute(
				"oneStageRandomAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"one-stage-random"));

		model.addAttribute(
				"oneStageRandomSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"one-stage-random"));

		model.addAttribute(
				"oneStageRandomSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"one-stage-random"));

		model.addAttribute(
				"oneStageRandomAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-stage-random"));

		model.addAttribute(
				"oneStageRandomAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"one-stage-random"));

		// =====================================================
		// 二段階認証 ランダム
		// =====================================================

		model.addAttribute(
				"twoStageRandomExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"two-stage-random"));

		model.addAttribute(
				"twoStageRandomSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"two-stage-random"));

		model.addAttribute(
				"twoStageRandomSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"two-stage-random"));

		model.addAttribute(
				"twoStageRandomAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"two-stage-random"));

		model.addAttribute(
				"twoStageRandomSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"two-stage-random"));

		model.addAttribute(
				"twoStageRandomSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"two-stage-random"));

		model.addAttribute(
				"twoStageRandomAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"two-stage-random"));

		model.addAttribute(
				"twoStageRandomAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"two-stage-random"));

		// =====================================================
		// 三段階認証 ランダム
		// =====================================================

		model.addAttribute(
				"threeStageRandomExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"three-stage-random"));

		model.addAttribute(
				"threeStageRandomSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"three-stage-random"));

		model.addAttribute(
				"threeStageRandomSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"three-stage-random"));

		model.addAttribute(
				"threeStageRandomAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"three-stage-random"));

		model.addAttribute(
				"threeStageRandomSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"three-stage-random"));

		model.addAttribute(
				"threeStageRandomSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"three-stage-random"));

		model.addAttribute(
				"threeStageRandomAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"three-stage-random"));

		model.addAttribute(
				"threeStageRandomAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"three-stage-random"));

		// =====================================================
		// 一段階認証 辞書攻撃
		// =====================================================

		model.addAttribute(
				"oneStageDictionaryExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"one-stage-dictionary"));

		model.addAttribute(
				"oneStageDictionarySuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"one-stage-dictionary"));

		model.addAttribute(
				"oneStageDictionarySuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"one-stage-dictionary"));

		model.addAttribute(
				"oneStageDictionaryAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"one-stage-dictionary"));

		model.addAttribute(
				"oneStageDictionarySuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"one-stage-dictionary"));

		model.addAttribute(
				"oneStageDictionarySuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"one-stage-dictionary"));

		model.addAttribute(
				"oneStageDictionaryAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"one-stage-dictionary"));

		model.addAttribute(
				"oneStageDictionaryAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"one-stage-dictionary"));

		// =====================================================
		// 二要素認証 Password + Email OTP ランダム
		// =====================================================

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomExperimentCount",
				experimentResultService
				.getExperimentCountByAuthMethod(
						"two-factor-password-email-otp-random"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomSuccessCount",
				experimentResultService
				.getSuccessCountByAuthMethod(
						"two-factor-password-email-otp-random"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomSuccessRate",
				experimentResultService
				.getSuccessRateByAuthMethod(
						"two-factor-password-email-otp-random"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomAverageAttemptCount",
				experimentResultService
				.getAverageAttemptCountByAuthMethod(
						"two-factor-password-email-otp-random"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomSuccessAttackTimeTotal",
				experimentResultService
				.getSuccessAttackTimeTotalByAuthMethod(
						"two-factor-password-email-otp-random"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomSuccessAttackTimeTotalFormatted",
				experimentResultService
				.getSuccessAttackTimeTotalFormattedByAuthMethod(
						"two-factor-password-email-otp-random"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomAverageSuccessAttackTime",
				experimentResultService
				.getAverageSuccessAttackTimeByAuthMethod(
						"two-factor-password-email-otp-random"));

		model.addAttribute(
				"twoFactorPasswordEmailOtpRandomAverageSuccessAttackTimeFormatted",
				experimentResultService
				.getAverageSuccessAttackTimeFormattedByAuthMethod(
						"two-factor-password-email-otp-random"));

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

		}

		else if (result.getStageCount() == 2) {

			return result.getPassword()
					+ " → "
					+ result.getPassword2();

		}

		else if (result.getStageCount() == 3) {

			return result.getPassword()
					+ " → "
					+ result.getPassword2()
					+ " → "
					+ result.getPassword3();
		}

		return null;
	}

	// =========================================================
	// ランダム二段階認証の認証情報
	// =========================================================

	private String createRandomTwoStageCredential(
			String password,
			String password2) {

		if (password != null
				&& !password.isBlank()
				&& password2 != null
				&& !password2.isBlank()) {

			return password
					+ " → "
					+ password2;
		}

		if (password != null
				&& !password.isBlank()) {

			return password;
		}

		if (password2 != null
				&& !password2.isBlank()) {

			return password2;
		}

		return null;
	}

	// =========================================================
	// ランダム三段階認証の認証情報
	// =========================================================

	private String createRandomThreeStageCredential(
			String password,
			String password2,
			String password3) {

		if (password != null
				&& !password.isBlank()
				&& password2 != null
				&& !password2.isBlank()
				&& password3 != null
				&& !password3.isBlank()) {

			return password
					+ " → "
					+ password2
					+ " → "
					+ password3;
		}

		if (password != null
				&& !password.isBlank()
				&& password2 != null
				&& !password2.isBlank()) {

			return password
					+ " → "
					+ password2;
		}

		if (password != null
				&& !password.isBlank()) {

			return password;
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

		}

		else if (result.getStageCount() == 2) {

			return "ID + Password → Password2";

		}

		else if (result.getStageCount() == 3) {

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