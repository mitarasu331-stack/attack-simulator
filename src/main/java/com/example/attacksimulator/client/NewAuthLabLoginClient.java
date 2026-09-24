package com.example.attacksimulator.client;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.springframework.stereotype.Component;

@Component
public class NewAuthLabLoginClient {

	private static final String NEW_AUTH_LAB_URL =
			"http://localhost:8080";

	private final CookieManager cookieManager;
	private final HttpClient httpClient;

	public NewAuthLabLoginClient() {

		this.cookieManager =
				new CookieManager();

		this.cookieManager.setCookiePolicy(
				CookiePolicy.ACCEPT_ALL);

		this.httpClient =
				HttpClient.newBuilder()
				.cookieHandler(cookieManager)
				.followRedirects(
						HttpClient.Redirect.NORMAL)
				.build();
	}

	// =========================================================
	// 一段階認証
	// =========================================================

	public LoginResult loginOneStage(
			String username,
			String password) {

		// 前回のセッションを削除
		cookieManager.getCookieStore().removeAll();

		System.out.println(
				"===== loginOneStage 呼び出し =====");

		System.out.println(
				"username = " + username);

		System.out.println(
				"password = " + password);

		try {

			String requestBody =
					"username="
							+ URLEncoder.encode(
									username,
									StandardCharsets.UTF_8)
							+ "&password="
									+ URLEncoder.encode(
											password,
											StandardCharsets.UTF_8);

			HttpRequest request =
					HttpRequest.newBuilder()
					.uri(URI.create(
							NEW_AUTH_LAB_URL
							+ "/login/one-stage"))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(
									requestBody,
									StandardCharsets.UTF_8))
					.build();

			System.out.println(
					"POST /login/one-stage を送信");

			HttpResponse<String> response =
					httpClient.send(
							request,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			URI responseUri =
					response.uri();

			System.out.println(
					"HTTP Status = "
							+ response.statusCode());

			System.out.println(
					"Final URL = "
							+ responseUri);

			boolean success =
					"/home".equals(
							responseUri.getPath());

			System.out.println(
					"実ログイン成功 = "
							+ success);

			System.out.println(
					"================================");

			return new LoginResult(
					success,
					response.statusCode(),
					responseUri.toString(),
					response.body());

		} catch (IOException e) {

			e.printStackTrace();

			return new LoginResult(
					false,
					-1,
					null,
					"通信エラー: "
							+ e.getMessage());

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			e.printStackTrace();

			return new LoginResult(
					false,
					-1,
					null,
					"通信が中断されました: "
							+ e.getMessage());
		}
	}

	// =========================================================
	// 二段階認証
	// Password → Password2
	// =========================================================

	public LoginResult loginTwoStage(
			String username,
			String password,
			String password2) {

		// 二段階認証を開始する前に
		// 前回のセッションを削除
		cookieManager.getCookieStore().removeAll();

		System.out.println(
				"===== loginTwoStage 呼び出し =====");

		System.out.println(
				"username = " + username);

		System.out.println(
				"password = " + password);

		System.out.println(
				"password2 = " + password2);

		try {

			// -------------------------------------------------
			// 1段階目
			// Password
			// -------------------------------------------------

			String firstRequestBody =
					"username="
							+ URLEncoder.encode(
									username,
									StandardCharsets.UTF_8)
							+ "&password="
									+ URLEncoder.encode(
											password,
											StandardCharsets.UTF_8);

			HttpRequest firstRequest =
					HttpRequest.newBuilder()
					.uri(URI.create(
							NEW_AUTH_LAB_URL
							+ "/login/two-stage"))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(
									firstRequestBody,
									StandardCharsets.UTF_8))
					.build();

			System.out.println(
					"POST /login/two-stage を送信");

			HttpResponse<String> firstResponse =
					httpClient.send(
							firstRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"1段階目 HTTP Status = "
							+ firstResponse.statusCode());

			System.out.println(
					"1段階目 Final URL = "
							+ firstResponse.uri());

			// -------------------------------------------------
			// 1段階目失敗
			// -------------------------------------------------

			if (!firstResponse.uri()
					.getPath()
					.equals(
							"/login/two-stage/password2")) {

				System.out.println(
						"1段階目の認証に失敗しました。");

				return new LoginResult(
						false,
						firstResponse.statusCode(),
						firstResponse.uri().toString(),
						firstResponse.body());
			}

			// -------------------------------------------------
			// 2段階目
			// Password2
			// -------------------------------------------------

			String secondRequestBody =
					"password2="
							+ URLEncoder.encode(
									password2,
									StandardCharsets.UTF_8);

			HttpRequest secondRequest =
					HttpRequest.newBuilder()
					.uri(URI.create(
							NEW_AUTH_LAB_URL
							+ "/login/two-stage/password2"))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(
									secondRequestBody,
									StandardCharsets.UTF_8))
					.build();

			System.out.println(
					"POST /login/two-stage/password2 を送信");

			HttpResponse<String> secondResponse =
					httpClient.send(
							secondRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"2段階目 HTTP Status = "
							+ secondResponse.statusCode());

			System.out.println(
					"2段階目 Final URL = "
							+ secondResponse.uri());

			// -------------------------------------------------
			// 最終的に /home なら成功
			// -------------------------------------------------

			boolean success =
					"/home".equals(
							secondResponse.uri().getPath());

			System.out.println(
					"実ログイン成功 = "
							+ success);

			System.out.println(
					"================================");

			return new LoginResult(
					success,
					secondResponse.statusCode(),
					secondResponse.uri().toString(),
					secondResponse.body());

		} catch (IOException e) {

			e.printStackTrace();

			return new LoginResult(
					false,
					-1,
					null,
					"通信エラー: "
							+ e.getMessage());

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			e.printStackTrace();

			return new LoginResult(
					false,
					-1,
					null,
					"通信が中断されました: "
							+ e.getMessage());
		}
	}

	// =========================================================
	// 三段階認証
	// Password → Password2 → Password3
	// =========================================================

	public LoginResult loginThreeStage(
			String username,
			String password,
			String password2,
			String password3) {

		// 前回のセッションを削除
		cookieManager.getCookieStore().removeAll();

		System.out.println(
				"===== loginThreeStage 呼び出し =====");

		System.out.println(
				"username = " + username);

		System.out.println(
				"password = " + password);

		System.out.println(
				"password2 = " + password2);

		System.out.println(
				"password3 = " + password3);

		try {

			// =================================================
			// 1段階目
			// Password
			// =================================================

			String firstRequestBody =
					"username="
							+ URLEncoder.encode(
									username,
									StandardCharsets.UTF_8)
							+ "&password="
									+ URLEncoder.encode(
											password,
											StandardCharsets.UTF_8);

			HttpRequest firstRequest =
					HttpRequest.newBuilder()
					.uri(URI.create(
							NEW_AUTH_LAB_URL
							+ "/login/three-stage"))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(
									firstRequestBody,
									StandardCharsets.UTF_8))
					.build();

			System.out.println(
					"POST /login/three-stage を送信");

			HttpResponse<String> firstResponse =
					httpClient.send(
							firstRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"1段階目 HTTP Status = "
							+ firstResponse.statusCode());

			System.out.println(
					"1段階目 Final URL = "
							+ firstResponse.uri());

			// 1段階目失敗
			if (!firstResponse.uri()
					.getPath()
					.equals(
							"/login/three-stage/password2")) {

				System.out.println(
						"1段階目の認証に失敗しました。");

				return new LoginResult(
						false,
						firstResponse.statusCode(),
						firstResponse.uri().toString(),
						firstResponse.body());
			}

			// =================================================
			// 2段階目
			// Password2
			// =================================================

			String secondRequestBody =
					"password2="
							+ URLEncoder.encode(
									password2,
									StandardCharsets.UTF_8);

			HttpRequest secondRequest =
					HttpRequest.newBuilder()
					.uri(URI.create(
							NEW_AUTH_LAB_URL
							+ "/login/three-stage/password2"))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(
									secondRequestBody,
									StandardCharsets.UTF_8))
					.build();

			System.out.println(
					"POST /login/three-stage/password2 を送信");

			HttpResponse<String> secondResponse =
					httpClient.send(
							secondRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"2段階目 HTTP Status = "
							+ secondResponse.statusCode());

			System.out.println(
					"2段階目 Final URL = "
							+ secondResponse.uri());

			// 2段階目失敗
			if (!secondResponse.uri()
					.getPath()
					.equals(
							"/login/three-stage/password3")) {

				System.out.println(
						"2段階目の認証に失敗しました。");

				return new LoginResult(
						false,
						secondResponse.statusCode(),
						secondResponse.uri().toString(),
						secondResponse.body());
			}

			// =================================================
			// 3段階目
			// Password3
			// =================================================

			String thirdRequestBody =
					"password3="
							+ URLEncoder.encode(
									password3,
									StandardCharsets.UTF_8);

			HttpRequest thirdRequest =
					HttpRequest.newBuilder()
					.uri(URI.create(
							NEW_AUTH_LAB_URL
							+ "/login/three-stage/password3"))
					.header(
							"Content-Type",
							"application/x-www-form-urlencoded")
					.POST(
							HttpRequest.BodyPublishers
							.ofString(
									thirdRequestBody,
									StandardCharsets.UTF_8))
					.build();

			System.out.println(
					"POST /login/three-stage/password3 を送信");

			HttpResponse<String> thirdResponse =
					httpClient.send(
							thirdRequest,
							HttpResponse.BodyHandlers
							.ofString(
									StandardCharsets.UTF_8));

			System.out.println(
					"3段階目 HTTP Status = "
							+ thirdResponse.statusCode());

			System.out.println(
					"3段階目 Final URL = "
							+ thirdResponse.uri());

			// =================================================
			// 最終的に /home なら成功
			// =================================================

			boolean success =
					"/home".equals(
							thirdResponse.uri()
							.getPath());

			System.out.println(
					"実ログイン成功 = "
							+ success);

			System.out.println(
					"================================");

			return new LoginResult(
					success,
					thirdResponse.statusCode(),
					thirdResponse.uri().toString(),
					thirdResponse.body());

		} catch (IOException e) {

			e.printStackTrace();

			return new LoginResult(
					false,
					-1,
					null,
					"通信エラー: "
							+ e.getMessage());

		} catch (InterruptedException e) {

			Thread.currentThread().interrupt();

			e.printStackTrace();

			return new LoginResult(
					false,
					-1,
					null,
					"通信が中断されました: "
							+ e.getMessage());
		}
	}

	// =========================================================
	// ログイン結果
	// =========================================================

	public static class LoginResult {

		private final boolean success;
		private final int statusCode;
		private final String finalUrl;
		private final String responseBody;

		public LoginResult(
				boolean success,
				int statusCode,
				String finalUrl,
				String responseBody) {

			this.success = success;
			this.statusCode = statusCode;
			this.finalUrl = finalUrl;
			this.responseBody = responseBody;
		}

		public boolean isSuccess() {
			return success;
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
	}
}