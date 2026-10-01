package com.example.attacksimulator.client;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import org.springframework.stereotype.Component;

@Component
public class NewAuthLabLoginClient {

	// =========================================================
	// NewAuthLab URL
	// =========================================================

	private static final String BASE_URL =
			"http://localhost:8080";

	// =========================================================
	// 通常ログイン用
	// =========================================================

	private static final String ONE_STAGE_LOGIN_URL =
			BASE_URL + "/login/one-stage";

	private static final String TWO_STAGE_LOGIN_URL =
			BASE_URL + "/login/two-stage";

	private static final String THREE_STAGE_LOGIN_URL =
			BASE_URL + "/login/three-stage";

	// =========================================================
	// One Factor Email OTP
	// =========================================================

	private static final String SEND_OTP_URL =
			BASE_URL + "/send-otp";

	private static final String VERIFY_OTP_URL =
			BASE_URL + "/verify-otp";

	// =========================================================
	// 二要素認証
	// AttackSimulator専用エンドポイント
	// =========================================================

	private static final String TWO_FACTOR_ATTACK_PASSWORD_URL =
			BASE_URL + "/login/two-factor/attack/password";

	private static final String TWO_FACTOR_ATTACK_VERIFY_OTP_URL =
			BASE_URL + "/login/two-factor/attack/verify-otp";

	// =========================================================
	// HTTP Client
	// =========================================================

	/**
	 * 通常のHTTP通信
	 *
	 * リダイレクトを追従する。
	 */
	private final HttpClient httpClient;

	/**
	 * リダイレクトを追従しないHTTP通信
	 *
	 * Locationヘッダーを確認したい処理で使用する。
	 */
	private final HttpClient noRedirectHttpClient;

	/**
	 * Cookie管理
	 *
	 * Password認証 → OTP認証など、
	 * 同じセッションを維持するために使用する。
	 */
	private final java.net.CookieManager cookieManager;

	// =========================================================
	// コンストラクタ
	// =========================================================

	public NewAuthLabLoginClient() {

		cookieManager =
				new java.net.CookieManager(
						null,
						java.net.CookiePolicy.ACCEPT_ALL);

		httpClient =
				HttpClient.newBuilder()
				.connectTimeout(
						Duration.ofSeconds(60))
				.followRedirects(
						HttpClient.Redirect.NORMAL)
				.cookieHandler(
						cookieManager)
				.build();

		noRedirectHttpClient =
				HttpClient.newBuilder()
				.connectTimeout(
						Duration.ofSeconds(60))
				.followRedirects(
						HttpClient.Redirect.NEVER)
				.cookieHandler(
						cookieManager)
				.build();
	}

	// =========================================================
	// One Stage Login
	// =========================================================

	public LoginResult loginOneStage(
			String username,
			String password) {

		clearCookies();

		String body =
				"username=" + encode(username)
				+ "&password=" + encode(password)
				+ "&fromAttackSimulator=true";

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(
						URI.create(
								ONE_STAGE_LOGIN_URL))
				.timeout(
						Duration.ofSeconds(60))
				.header(
						"Content-Type",
						"application/x-www-form-urlencoded")
				.POST(
						HttpRequest.BodyPublishers
						.ofString(body))
				.build();

		try {

			HttpResponse<String> response =
					httpClient.send(
							request,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			String finalUrl =
					response.uri().toString();

			boolean success =
					isSuccessfulLoginUrl(
							finalUrl,
							"/login/one-stage");

			System.out.println(
					"===== 一段階認証結果 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"HTTP Status = "
							+ response.statusCode());

			System.out.println(
					"Final URL = "
							+ finalUrl);

			System.out.println(
					"ログイン成功 = "
							+ success);

			System.out.println(
					"==========================");

			return new LoginResult(
					success,
					response.statusCode(),
					finalUrl,
					response.body(),
					getSessionCookie());

		} catch (IOException e) {

			System.out.println(
					"一段階認証通信エラー");

			System.out.println(
					"エラー = "
							+ e.getClass().getName());

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					ONE_STAGE_LOGIN_URL,
					e.getMessage(),
					null);

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			System.out.println(
					"一段階認証通信が中断されました。");

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					ONE_STAGE_LOGIN_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// Two Stage Login
	// =========================================================

	public LoginResult loginTwoStage(
			String username,
			String password,
			String password2) {

		clearCookies();

		try {

			// =====================================================
			// ① 1段階目
			// ID + Password
			// =====================================================

			String firstBody =
					"username=" + encode(username)
					+ "&password=" + encode(password)
					+ "&fromAttackSimulator=true";

			HttpRequest firstRequest =
					HttpRequest.newBuilder()
					.uri(
							URI.create(
									TWO_STAGE_LOGIN_URL))
					.timeout(
							Duration.ofSeconds(60))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(firstBody))
					.build();

			HttpResponse<String> firstResponse =
					noRedirectHttpClient.send(
							firstRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"===== 二段階認証 1段階目 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"Password = "
							+ password);

			System.out.println(
					"HTTP Status = "
							+ firstResponse.statusCode());

			System.out.println(
					"Location = "
							+ firstResponse.headers()
							.firstValue("Location")
							.orElse("なし"));

			System.out.println(
					"==============================");

			// =====================================================
			// 1段階目で失敗した場合
			// =====================================================

			if (firstResponse.statusCode() < 300
					|| firstResponse.statusCode() >= 400) {

				return new LoginResult(
						false,
						firstResponse.statusCode(),
						firstResponse.uri().toString(),
						firstResponse.body(),
						getSessionCookie());
			}

			// =====================================================
			// ② 2段階目
			// Password2
			// =====================================================

			String secondBody =
					"password2=" + encode(password2)
					+ "&fromAttackSimulator=true";

			HttpRequest secondRequest =
					HttpRequest.newBuilder()
					.uri(
							URI.create(
									BASE_URL
									+ "/login/two-stage/password2"))
					.timeout(
							Duration.ofSeconds(60))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(secondBody))
					.build();

			HttpResponse<String> secondResponse =
					httpClient.send(
							secondRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			String finalUrl =
					secondResponse.uri().toString();

			boolean success =
					isSuccessfulLoginUrl(
							finalUrl,
							"/login/two-stage/password2");

			System.out.println(
					"===== 二段階認証 2段階目 =====");

			System.out.println(
					"Password2 = "
							+ password2);

			System.out.println(
					"HTTP Status = "
							+ secondResponse.statusCode());

			System.out.println(
					"Final URL = "
							+ finalUrl);

			System.out.println(
					"ログイン成功 = "
							+ success);

			System.out.println(
					"==============================");

			return new LoginResult(
					success,
					secondResponse.statusCode(),
					finalUrl,
					secondResponse.body(),
					getSessionCookie());

		} catch (IOException e) {

			System.out.println(
					"二段階認証通信エラー");

			System.out.println(
					"エラー = "
							+ e.getClass().getName());

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					TWO_STAGE_LOGIN_URL,
					e.getMessage(),
					null);

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			System.out.println(
					"二段階認証通信が中断されました。");

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					TWO_STAGE_LOGIN_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// Three Stage Login
	// =========================================================

	public LoginResult loginThreeStage(
			String username,
			String password,
			String password2,
			String password3) {

		clearCookies();

		try {

			// =====================================================
			// ① 1段階目
			// ID + Password
			// =====================================================

			String firstBody =
					"username=" + encode(username)
					+ "&password=" + encode(password)
					+ "&fromAttackSimulator=true";

			HttpRequest firstRequest =
					HttpRequest.newBuilder()
					.uri(
							URI.create(
									THREE_STAGE_LOGIN_URL))
					.timeout(
							Duration.ofSeconds(60))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(firstBody))
					.build();

			HttpResponse<String> firstResponse =
					noRedirectHttpClient.send(
							firstRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"===== 三段階認証 1段階目 =====");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"Password = "
							+ password);

			System.out.println(
					"HTTP Status = "
							+ firstResponse.statusCode());

			System.out.println(
					"Location = "
							+ firstResponse.headers()
							.firstValue("Location")
							.orElse("なし"));

			System.out.println(
					"==============================");

			// =====================================================
			// 1段階目失敗
			// =====================================================

			if (firstResponse.statusCode() < 300
					|| firstResponse.statusCode() >= 400) {

				return new LoginResult(
						false,
						firstResponse.statusCode(),
						firstResponse.uri().toString(),
						firstResponse.body(),
						getSessionCookie());
			}

			// =====================================================
			// ② 2段階目
			// Password2
			// =====================================================

			String secondBody =
					"password2=" + encode(password2)
					+ "&fromAttackSimulator=true";

			HttpRequest secondRequest =
					HttpRequest.newBuilder()
					.uri(
							URI.create(
									BASE_URL
									+ "/login/three-stage/password2"))
					.timeout(
							Duration.ofSeconds(60))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(secondBody))
					.build();

			HttpResponse<String> secondResponse =
					noRedirectHttpClient.send(
							secondRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"===== 三段階認証 2段階目 =====");

			System.out.println(
					"Password2 = "
							+ password2);

			System.out.println(
					"HTTP Status = "
							+ secondResponse.statusCode());

			System.out.println(
					"Location = "
							+ secondResponse.headers()
							.firstValue("Location")
							.orElse("なし"));

			System.out.println(
					"==============================");

			// =====================================================
			// 2段階目失敗
			// =====================================================

			if (secondResponse.statusCode() < 300
					|| secondResponse.statusCode() >= 400) {

				return new LoginResult(
						false,
						secondResponse.statusCode(),
						secondResponse.uri().toString(),
						secondResponse.body(),
						getSessionCookie());
			}

			// =====================================================
			// ③ 3段階目
			// Password3
			// =====================================================

			String thirdBody =
					"password3=" + encode(password3)
					+ "&fromAttackSimulator=true";

			HttpRequest thirdRequest =
					HttpRequest.newBuilder()
					.uri(
							URI.create(
									BASE_URL
									+ "/login/three-stage/password3"))
					.timeout(
							Duration.ofSeconds(60))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(thirdBody))
					.build();

			HttpResponse<String> thirdResponse =
					httpClient.send(
							thirdRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			String finalUrl =
					thirdResponse.uri().toString();

			boolean success =
					isSuccessfulLoginUrl(
							finalUrl,
							"/login/three-stage/password3");

			System.out.println(
					"===== 三段階認証 3段階目 =====");

			System.out.println(
					"Password3 = "
							+ password3);

			System.out.println(
					"HTTP Status = "
							+ thirdResponse.statusCode());

			System.out.println(
					"Final URL = "
							+ finalUrl);

			System.out.println(
					"ログイン成功 = "
							+ success);

			System.out.println(
					"==============================");

			return new LoginResult(
					success,
					thirdResponse.statusCode(),
					finalUrl,
					thirdResponse.body(),
					getSessionCookie());

		} catch (IOException e) {

			System.out.println(
					"三段階認証通信エラー");

			System.out.println(
					"エラー = "
							+ e.getClass().getName());

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					THREE_STAGE_LOGIN_URL,
					e.getMessage(),
					null);

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			System.out.println(
					"三段階認証通信が中断されました。");

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					THREE_STAGE_LOGIN_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// ログイン成功判定
	// =========================================================

	private boolean isSuccessfulLoginUrl(
			String finalUrl,
			String loginPath) {

		if (finalUrl == null
				|| finalUrl.isBlank()) {

			return false;
		}

		try {

			URI uri =
					URI.create(finalUrl);

			String path =
					uri.getPath();

			/*
			 * 現在のnewauthlabでは、
			 * ログイン成功後は redirect:/ となる。
			 *
			 * /home や /index を使用する構成にも
			 * 対応できるようにしている。
			 */
			if ("/".equals(path)
					|| "/home".equals(path)
					|| "/index".equals(path)) {

				return true;
			}

			/*
			 * ログイン画面に戻っている場合は失敗。
			 */
			if (loginPath.equals(path)) {

				return false;
			}

			/*
			 * その他のURLも、
			 * 認証成功とは判定しない。
			 */
			return false;

		} catch (Exception e) {

			return false;
		}
	}

	// =========================================================
	// Email OTP送信
	// One Factor Email OTP用
	// =========================================================

	public LoginResult sendEmailOtp(
			String username,
			String email) {

		// -----------------------------------------------------
		// OTP発行開始前にCookieをクリア
		// -----------------------------------------------------

		clearCookies();

		System.out.println();
		System.out.println(
				"========================================");
		System.out.println(
				"【DEBUG】/send-otp 開始");
		System.out.println(
				"========================================");

		System.out.println(
				"送信対象username = "
						+ username);

		System.out.println(
				"送信先Email = "
						+ email);

		System.out.println(
				"送信前Session Cookie = "
						+ getSessionCookie());

		System.out.println(
				"========================================");

		/*
		 * username + email + fromAttackSimulator
		 *
		 * usernameはOTP認証成功後に
		 * 対象ユーザーを特定するために使用する。
		 *
		 * emailは実際のOTP送信先。
		 */
		String body =
				"username=" + encode(username)
				+ "&email=" + encode(email)
				+ "&fromAttackSimulator=true";

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(
						URI.create(
								SEND_OTP_URL))
				.timeout(
						Duration.ofSeconds(60))
				.header(
						"Content-Type",
						"application/x-www-form-urlencoded")
				.POST(
						HttpRequest.BodyPublishers
						.ofString(body))
				.build();

		try {

			HttpResponse<String> response =
					noRedirectHttpClient.send(
							request,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			String location =
					response.headers()
					.firstValue("Location")
					.orElse(
							response.uri().toString());

			// -------------------------------------------------
			// OTP送信後のCookie確認
			// -------------------------------------------------

			System.out.println();
			System.out.println(
					"========================================");
			System.out.println(
					"【DEBUG】/send-otp 完了");
			System.out.println(
					"========================================");

			System.out.println(
					"送信対象username = "
							+ username);

			System.out.println(
					"送信先Email = "
							+ email);

			System.out.println(
					"HTTP Status = "
							+ response.statusCode());

			System.out.println(
					"Location = "
							+ location);

			System.out.println(
					"送信後Session Cookie = "
							+ getSessionCookie());

			System.out.println(
					"Response Body = "
							+ response.body());

			System.out.println(
					"========================================");

			return new LoginResult(
					response.statusCode() >= 200
					&& response.statusCode() < 400,
					response.statusCode(),
					location,
					response.body(),
					getSessionCookie());

		} catch (IOException e) {

			System.out.println(
					"Email OTP送信通信エラー");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"email = "
							+ email);

			System.out.println(
					"エラー = "
							+ e.getClass().getName());

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					SEND_OTP_URL,
					e.getMessage(),
					null);

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			System.out.println(
					"Email OTP送信通信が中断されました。");

			System.out.println(
					"username = "
							+ username);

			System.out.println(
					"email = "
							+ email);

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					SEND_OTP_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// Email OTP確認
	// One Factor Email OTP用
	// =========================================================

	public LoginResult verifyEmailOtp(
			String otp) {

		// -----------------------------------------------------
		// 検証前のCookie確認
		// -----------------------------------------------------

		System.out.println();
		System.out.println(
				"========================================");
		System.out.println(
				"【DEBUG】/verify-otp 送信前");
		System.out.println(
				"========================================");

		System.out.println(
				"送信OTP = "
						+ otp);

		System.out.println(
				"検証前Session Cookie = "
						+ getSessionCookie());

		System.out.println(
				"========================================");

		String body =
				"otp=" + encode(otp);

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(
						URI.create(
								VERIFY_OTP_URL))
				.timeout(
						Duration.ofSeconds(60))
				.header(
						"Content-Type",
						"application/x-www-form-urlencoded")
				.POST(
						HttpRequest.BodyPublishers
						.ofString(body))
				.build();

		try {

			HttpResponse<String> response =
					noRedirectHttpClient.send(
							request,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			// =====================================================
			// レスポンス情報取得
			// =====================================================

			int statusCode =
					response.statusCode();

			String location =
					response.headers()
					.firstValue("Location")
					.orElse("");

			String responseBody =
					response.body() == null
					? ""
					: response.body();

			// =====================================================
			// デバッグ表示
			// =====================================================

			System.out.println();
			System.out.println(
					"========================================");
			System.out.println(
					"【DEBUG】AttackSimulator /verify-otp");
			System.out.println(
					"========================================");

			System.out.println(
					"送信OTP = "
							+ otp);

			System.out.println(
					"HTTP Status = "
							+ statusCode);

			System.out.println(
					"Location = "
							+ location);

			System.out.println(
					"Response Body = "
							+ responseBody);

			System.out.println(
					"Session Cookie = "
							+ getSessionCookie());

			System.out.println(
					"========================================");

			// =====================================================
			// 成功判定
			// =====================================================

			boolean redirectStatus =
					statusCode >= 300
					&& statusCode < 400;

			boolean attackLoginRedirect =
					location.contains(
							"/attack-login?ticket=");

			boolean success =
					redirectStatus
					&& attackLoginRedirect;

			System.out.println(
					"【DEBUG】redirectStatus = "
							+ redirectStatus);

			System.out.println(
					"【DEBUG】attackLoginRedirect = "
							+ attackLoginRedirect);

			System.out.println(
					"【DEBUG】verifyEmailOtp success = "
							+ success);

			// =====================================================
			// 成功した場合
			// =====================================================

			if (success) {

				System.out.println();
				System.out.println(
						"****************************************");
				System.out.println(
						"★★★ Email OTP認証成功を検出 ★★★");
				System.out.println(
						"OTP = "
								+ otp);
				System.out.println(
						"HTTP Status = "
								+ statusCode);
				System.out.println(
						"Location = "
								+ location);
				System.out.println(
						"****************************************");
				System.out.println();

			} else {

				System.out.println(
						"OTP認証失敗");

				System.out.println(
						"OTP = "
								+ otp);

				System.out.println(
						"HTTP Status = "
								+ statusCode);

				System.out.println(
						"Location = "
								+ location);
			}

			return new LoginResult(
					success,
					statusCode,
					location,
					responseBody,
					getSessionCookie());

		} catch (IOException e) {

			System.out.println(
					"Email OTP確認通信エラー");

			System.out.println(
					"OTP = "
							+ otp);

			System.out.println(
					"エラー = "
							+ e.getClass().getName());

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					VERIFY_OTP_URL,
					e.getMessage(),
					null);

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			System.out.println(
					"Email OTP確認通信が中断されました。");

			System.out.println(
					"OTP = "
							+ otp);

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					VERIFY_OTP_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// AttackSimulator専用
	// =========================================================

	/**
	 * 二要素認証のPassword部分だけを実行する。
	 *
	 * Passwordが正しい場合、
	 * NewAuthLab側でOTPが発行される。
	 *
	 * OTPの総当たり処理は
	 * EmailOtpBruteForceAttack側で行う。
	 */
	public LoginResult loginTwoFactorPassword(
			String username,
			String password) {

		clearCookies();

		System.out.println(
				"===== 二要素Password確認 =====");

		System.out.println(
				"username = "
						+ username);

		System.out.println(
				"==============================");

		String passwordBody =
				"username=" + encode(username)
				+ "&password=" + encode(password);

		HttpRequest passwordRequest =
				HttpRequest.newBuilder()
				.uri(
						URI.create(
								TWO_FACTOR_ATTACK_PASSWORD_URL))
				.timeout(
						Duration.ofSeconds(60))
				.header(
						"Content-Type",
						"application/x-www-form-urlencoded")
				.POST(
						HttpRequest.BodyPublishers
						.ofString(passwordBody))
				.build();

		try {

			HttpResponse<String> passwordResponse =
					noRedirectHttpClient.send(
							passwordRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			String responseBody =
					passwordResponse.body() == null
					? ""
					: passwordResponse.body().trim();

			System.out.println(
					"===== 二要素Passwordレスポンス =====");

			System.out.println(
					"HTTP Status = "
							+ passwordResponse.statusCode());

			System.out.println(
					"Body = "
							+ responseBody);

			System.out.println(
					"====================================");

			if (passwordResponse.statusCode() < 200
					|| passwordResponse.statusCode() >= 300) {

				return new LoginResult(
						false,
						passwordResponse.statusCode(),
						passwordResponse.uri().toString(),
						responseBody,
						null,
						0,
						getSessionCookie());
			}

			if ("OTP_SENT".equals(responseBody)) {

				System.out.println(
						"Password認証成功");

				System.out.println(
						"OTP_SENTを確認しました。");

				return new LoginResult(
						true,
						passwordResponse.statusCode(),
						passwordResponse.uri().toString(),
						responseBody,
						null,
						0,
						getSessionCookie());
			}

			System.out.println(
					"Password認証失敗");

			return new LoginResult(
					false,
					passwordResponse.statusCode(),
					passwordResponse.uri().toString(),
					responseBody,
					null,
					0,
					getSessionCookie());

		} catch (IOException e) {

			System.out.println(
					"二要素Password通信エラー");

			System.out.println(
					"エラー = "
							+ e.getClass().getName());

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					TWO_FACTOR_ATTACK_PASSWORD_URL,
					e.getMessage(),
					null,
					0,
					getSessionCookie());

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			System.out.println(
					"二要素Password通信が中断されました。");

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					TWO_FACTOR_ATTACK_PASSWORD_URL,
					e.getMessage(),
					null,
					0,
					getSessionCookie());
		}
	}

	// =========================================================
	// 二要素認証
	// Email OTP確認
	// =========================================================

	/**
	 * 二要素認証のOTPを1回だけ検証する。
	 *
	 * OTPの000000～999999の総当たり処理は
	 * EmailOtpBruteForceAttack側で行う。
	 */
	public LoginResult verifyTwoFactorOtp(
			String otp) {

		String body =
				"otp=" + encode(otp);

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(
						URI.create(
								TWO_FACTOR_ATTACK_VERIFY_OTP_URL))
				.timeout(
						Duration.ofSeconds(60))
				.header(
						"Content-Type",
						"application/x-www-form-urlencoded")
				.POST(
						HttpRequest.BodyPublishers
						.ofString(body))
				.build();

		try {

			HttpResponse<String> response =
					noRedirectHttpClient.send(
							request,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			String location =
					response.headers()
					.firstValue("Location")
					.orElse(
							response.uri()
							.toString());

			boolean success =
					response.statusCode() >= 300
					&& response.statusCode() < 400
					&& (
							location.startsWith(
									BASE_URL
									+ "/attack-login?ticket=")
							||
							location.startsWith(
									"/attack-login?ticket=")
							);

			if (success) {

				System.out.println(
						"二要素OTP成功");

				System.out.println(
						"OTP = "
								+ otp);

				System.out.println(
						"Location = "
								+ location);
			}

			return new LoginResult(
					success,
					response.statusCode(),
					location,
					response.body(),
					getSessionCookie());

		} catch (IOException e) {

			System.out.println(
					"OTP確認通信エラー");

			System.out.println(
					"OTP = "
							+ otp);

			System.out.println(
					"エラー = "
							+ e.getClass().getName());

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					TWO_FACTOR_ATTACK_VERIFY_OTP_URL,
					e.getMessage(),
					null);

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			System.out.println(
					"OTP確認通信が中断されました。");

			System.out.println(
					"OTP = "
							+ otp);

			System.out.println(
					"内容 = "
							+ e.getMessage());

			return new LoginResult(
					false,
					500,
					TWO_FACTOR_ATTACK_VERIFY_OTP_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// Cookie取得
	// =========================================================

	public String getSessionCookie() {

		try {

			List<java.net.HttpCookie> cookies =
					cookieManager
					.getCookieStore()
					.getCookies();

			for (java.net.HttpCookie cookie
					: cookies) {

				if ("JSESSIONID".equals(
						cookie.getName())) {

					return cookie.getName()
							+ "="
							+ cookie.getValue();
				}
			}

		} catch (Exception e) {

			System.out.println(
					"Cookie取得エラー = "
							+ e.getMessage());
		}

		return null;
	}

	// =========================================================
	// Cookie削除
	// =========================================================

	public void clearCookies() {

		cookieManager
		.getCookieStore()
		.removeAll();
	}

	// =========================================================
	// URLエンコード
	// =========================================================

	private String encode(
			String value) {

		if (value == null) {

			return "";
		}

		return URLEncoder.encode(
				value,
				StandardCharsets.UTF_8);
	}

	// =========================================================
	// LoginResult
	// =========================================================

	public static class LoginResult {

		private final boolean success;

		private final int statusCode;

		private final String finalUrl;

		private final String responseBody;

		private final String otp;

		private final int attemptCount;

		private final String sessionCookie;

		// -----------------------------------------------------
		// 通常ログイン用
		// -----------------------------------------------------

		public LoginResult(
				boolean success,
				int statusCode,
				String finalUrl,
				String responseBody,
				String sessionCookie) {

			this(
					success,
					statusCode,
					finalUrl,
					responseBody,
					null,
					0,
					sessionCookie);
		}

		// -----------------------------------------------------
		// OTP / 試行回数付き
		// -----------------------------------------------------

		public LoginResult(
				boolean success,
				int statusCode,
				String finalUrl,
				String responseBody,
				String otp,
				int attemptCount,
				String sessionCookie) {

			this.success =
					success;

			this.statusCode =
					statusCode;

			this.finalUrl =
					finalUrl;

			this.responseBody =
					responseBody;

			this.otp =
					otp;

			this.attemptCount =
					attemptCount;

			this.sessionCookie =
					sessionCookie;
		}

		// -----------------------------------------------------
		// Getter
		// -----------------------------------------------------

		public boolean isSuccess() {

			return success;
		}

		public boolean isRequestSuccess() {

			return statusCode >= 200
					&& statusCode < 400;
		}

		public int getStatusCode() {

			return statusCode;
		}

		public String getFinalUrl() {

			return finalUrl;
		}

		public String getResponseBody() {

			return responseBody;
		}

		public String getOtp() {

			return otp;
		}

		public int getAttemptCount() {

			return attemptCount;
		}

		public String getSessionCookie() {

			return sessionCookie;
		}
	}
}