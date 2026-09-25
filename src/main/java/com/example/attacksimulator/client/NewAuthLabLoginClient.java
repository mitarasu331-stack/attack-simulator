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
	 * Locationヘッダーを取得したい場合に使用する。
	 */
	private final HttpClient noRedirectHttpClient;

	/**
	 * Cookie管理
	 */
	private final java.net.CookieManager cookieManager;

	public NewAuthLabLoginClient() {

		cookieManager =
				new java.net.CookieManager(
						null,
						java.net.CookiePolicy.ACCEPT_ALL);

		httpClient =
				HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(10))
				.followRedirects(
						HttpClient.Redirect.NORMAL)
				.cookieHandler(cookieManager)
				.build();

		noRedirectHttpClient =
				HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(10))
				.followRedirects(
						HttpClient.Redirect.NEVER)
				.cookieHandler(cookieManager)
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
				.uri(URI.create(ONE_STAGE_LOGIN_URL))
				.timeout(Duration.ofSeconds(10))
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
							HttpResponse.BodyHandlers.ofString());

			return new LoginResult(
					response.statusCode() >= 200
					&& response.statusCode() < 400,
					response.statusCode(),
					response.uri().toString(),
					response.body(),
					getSessionCookie());

		} catch (IOException | InterruptedException e) {

			Thread.currentThread().interrupt();

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

		String body =
				"username=" + encode(username)
				+ "&password=" + encode(password)
				+ "&fromAttackSimulator=true"
				+ "&password2=" + encode(password2);

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(URI.create(TWO_STAGE_LOGIN_URL))
				.timeout(Duration.ofSeconds(10))
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
							HttpResponse.BodyHandlers.ofString());

			return new LoginResult(
					response.statusCode() >= 200
					&& response.statusCode() < 400,
					response.statusCode(),
					response.uri().toString(),
					response.body(),
					getSessionCookie());

		} catch (IOException | InterruptedException e) {

			Thread.currentThread().interrupt();

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

		String body =
				"username=" + encode(username)
				+ "&password=" + encode(password)
				+ "&password2=" + encode(password2)
				+ "&password3=" + encode(password3)
				+ "&fromAttackSimulator=true";

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(URI.create(THREE_STAGE_LOGIN_URL))
				.timeout(Duration.ofSeconds(10))
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
							HttpResponse.BodyHandlers.ofString());

			return new LoginResult(
					response.statusCode() >= 200
					&& response.statusCode() < 400,
					response.statusCode(),
					response.uri().toString(),
					response.body(),
					getSessionCookie());

		} catch (IOException | InterruptedException e) {

			Thread.currentThread().interrupt();

			return new LoginResult(
					false,
					500,
					THREE_STAGE_LOGIN_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// Email OTP送信
	// One Factor Email OTP用
	// =========================================================

	public LoginResult sendEmailOtp(
			String email) {

		clearCookies();

		String body =
				"email=" + encode(email)
				+ "&fromAttackSimulator=true";

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(URI.create(SEND_OTP_URL))
				.timeout(Duration.ofSeconds(10))
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
							HttpResponse.BodyHandlers.ofString());

			return new LoginResult(
					response.statusCode() >= 200
					&& response.statusCode() < 400,
					response.statusCode(),
					response.headers()
					.firstValue("Location")
					.orElse(response.uri().toString()),
					response.body(),
					getSessionCookie());

		} catch (IOException | InterruptedException e) {

			Thread.currentThread().interrupt();

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

		String body =
				"code=" + encode(otp);

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(URI.create(VERIFY_OTP_URL))
				.timeout(Duration.ofSeconds(10))
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
							HttpResponse.BodyHandlers.ofString());

			String location =
					response.headers()
					.firstValue("Location")
					.orElse(
							response.uri()
							.toString());

			boolean success =
					location.startsWith(
							BASE_URL + "/attack-login?ticket=");

			return new LoginResult(
					success,
					response.statusCode(),
					location,
					response.body(),
					getSessionCookie());

		} catch (IOException | InterruptedException e) {

			Thread.currentThread().interrupt();

			return new LoginResult(
					false,
					500,
					VERIFY_OTP_URL,
					e.getMessage(),
					null);
		}
	}

	// =========================================================
	// One Factor Email OTP
	// =========================================================

	public LoginResult loginOneFactorEmailOtp(
			String email,
			int maxOtpAttempts) {

		clearCookies();

		LoginResult sendResult =
				sendEmailOtp(email);

		if (!sendResult.isRequestSuccess()) {
			return sendResult;
		}

		int actualMaxAttempts =
				Math.max(
						1,
						Math.min(
								maxOtpAttempts,
								1_000_000));

		int attemptCount = 0;

		for (int i = 0;
				i < 1_000_000;
				i++) {

			if (attemptCount >= actualMaxAttempts) {
				break;
			}

			String candidate =
					String.format(
							"%06d",
							i);

			attemptCount++;

			LoginResult verifyResult =
					verifyEmailOtp(candidate);

			if (verifyResult.isSuccess()) {

				return new LoginResult(
						true,
						verifyResult.getStatusCode(),
						verifyResult.getFinalUrl(),
						verifyResult.getResponseBody(),
						candidate,
						attemptCount,
						getSessionCookie());
			}
		}

		return new LoginResult(
				false,
				200,
				VERIFY_OTP_URL,
				"Email OTP総当たりに失敗しました",
				null,
				attemptCount,
				getSessionCookie());
	}

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// AttackSimulator専用
	// =========================================================

	public LoginResult loginTwoFactorPasswordEmailOtp(
			String username,
			String password,
			int maxOtpAttempts) {

		clearCookies();

		System.out.println("========================================");
		System.out.println("二要素認証開始");
		System.out.println("username = " + username);
		System.out.println("OTP最大試行回数 = " + maxOtpAttempts);
		System.out.println("========================================");

		// -----------------------------------------------------
		// Password認証
		// -----------------------------------------------------

		String passwordBody =
				"username=" + encode(username)
				+ "&password=" + encode(password);

		HttpRequest passwordRequest =
				HttpRequest.newBuilder()
				.uri(
						URI.create(
								TWO_FACTOR_ATTACK_PASSWORD_URL))
				.timeout(Duration.ofSeconds(10))
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
							HttpResponse.BodyHandlers.ofString());

			System.out.println(
					"二要素Passwordレスポンス");
			System.out.println(
					"HTTP Status = "
							+ passwordResponse.statusCode());
			System.out.println(
					"Body = "
							+ passwordResponse.body());

			// -------------------------------------------------
			// Password認証失敗
			// -------------------------------------------------

			if (passwordResponse.statusCode() < 200
					|| passwordResponse.statusCode() >= 300) {

				return new LoginResult(
						false,
						passwordResponse.statusCode(),
						passwordResponse.uri().toString(),
						passwordResponse.body(),
						null,
						0,
						getSessionCookie());
			}

			if (!"OTP_SENT".equals(
					passwordResponse.body().trim())) {

				return new LoginResult(
						false,
						passwordResponse.statusCode(),
						passwordResponse.uri().toString(),
						passwordResponse.body(),
						null,
						0,
						getSessionCookie());
			}

			// -------------------------------------------------
			// OTP総当たり
			// -------------------------------------------------

			int actualMaxAttempts =
					Math.max(
							1,
							Math.min(
									maxOtpAttempts,
									1_000_000));

			int otpAttemptCount = 0;

			for (int i = 0;
					i < 1_000_000;
					i++) {

				if (otpAttemptCount
						>= actualMaxAttempts) {

					break;
				}

				String candidate =
						String.format(
								"%06d",
								i);

				otpAttemptCount++;

				LoginResult verifyResult =
						verifyTwoFactorOtp(candidate);

				if (verifyResult.isSuccess()) {

					System.out.println(
							"二要素OTP突破成功");
					System.out.println(
							"OTP = " + candidate);
					System.out.println(
							"OTP試行回数 = "
									+ otpAttemptCount);
					System.out.println(
							"========================================");

					return new LoginResult(
							true,
							verifyResult.getStatusCode(),
							verifyResult.getFinalUrl(),
							verifyResult.getResponseBody(),
							candidate,
							otpAttemptCount,
							getSessionCookie());
				}
			}

			// -------------------------------------------------
			// OTP最大試行回数到達
			// -------------------------------------------------

			return new LoginResult(
					false,
					200,
					TWO_FACTOR_ATTACK_VERIFY_OTP_URL,
					"Email OTP総当たりに失敗しました",
					null,
					otpAttemptCount,
					getSessionCookie());

		} catch (IOException | InterruptedException e) {

			Thread.currentThread().interrupt();

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
	// 二要素認証 OTP確認
	// =========================================================

	private LoginResult verifyTwoFactorOtp(
			String otp) {

		String body =
				"otp=" + encode(otp);

		HttpRequest request =
				HttpRequest.newBuilder()
				.uri(
						URI.create(
								TWO_FACTOR_ATTACK_VERIFY_OTP_URL))
				.timeout(Duration.ofSeconds(10))
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
							HttpResponse.BodyHandlers.ofString());

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

					return new LoginResult(
							success,
							response.statusCode(),
							location,
							response.body(),
							getSessionCookie());

		} catch (IOException | InterruptedException e) {

			Thread.currentThread().interrupt();

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
					cookieManager.getCookieStore()
					.getCookies();

			for (java.net.HttpCookie cookie : cookies) {

				if ("JSESSIONID".equals(
						cookie.getName())) {

					return cookie.getName()
							+ "="
							+ cookie.getValue();
				}
			}

		} catch (Exception ignored) {
		}

		return null;
	}

	// =========================================================
	// Cookie削除
	// =========================================================

	public void clearCookies() {

		cookieManager.getCookieStore()
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