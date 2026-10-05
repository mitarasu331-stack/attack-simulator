package com.example.attacksimulator.attack;

import java.security.SecureRandom;

import org.springframework.stereotype.Component;

@Component
public class RandomEmailOtpAttack {

	private static final int MIN_OTP = 0;

	private static final int MAX_OTP = 999_999;

	private static final int OTP_COUNT = 1_000_000;

	private final SecureRandom secureRandom =
			new SecureRandom();

	// =========================================================
	// Email OTP ランダム攻撃
	// =========================================================
	//
	// 000000 ～ 999999 をランダムな順番で試行
	// 同じOTPは二度試行しない
	//
	// verifyOtp は呼び出し元から渡してもらう
	// =========================================================

	public AttackResult execute(
			OtpVerifier otpVerifier,
			int maxAttempts) {

		maxAttempts =
				clampAttempts(maxAttempts);

		// =====================================================
		// 000000～999999を作成
		// =====================================================

		int[] candidates =
				createCandidates();

		// =====================================================
		// ランダムな順番にシャッフル
		// =====================================================

		shuffle(candidates);

		// =====================================================
		// OTP攻撃
		// =====================================================

		int attemptCount = 0;

		String otp = null;

		boolean success = false;

		for (int candidate : candidates) {

			if (attemptCount
					>= maxAttempts) {

				break;
			}

			attemptCount++;

			String candidateOtp =
					String.format(
							"%06d",
							candidate);

			// -------------------------------------------------
			// OTP候補は1件ずつ必ず表示
			// -------------------------------------------------

			System.out.println(
					"ランダムOTP 試行 "
							+ attemptCount
							+ " / "
							+ maxAttempts
							+ " : "
							+ candidateOtp);

			boolean verified =
					otpVerifier.verify(
							candidateOtp);

			if (verified) {

				otp = candidateOtp;

				success = true;

				break;
			}
		}

		return new AttackResult(
				success,
				otp,
				attemptCount);
	}

	// =========================================================
	// OTP候補作成
	// =========================================================

	private int[] createCandidates() {

		int[] candidates =
				new int[OTP_COUNT];

		for (int i = MIN_OTP;
				i <= MAX_OTP;
				i++) {

			candidates[i] = i;
		}

		return candidates;
	}

	// =========================================================
	// Fisher-Yatesシャッフル
	// =========================================================

	private void shuffle(
			int[] array) {

		for (int i = array.length - 1;
				i > 0;
				i--) {

			int j =
					secureRandom.nextInt(
							i + 1);

			int temp =
					array[i];

			array[i] =
					array[j];

			array[j] =
					temp;
		}
	}

	// =========================================================
	// 最大試行回数
	// 1～1000000
	// =========================================================

	private int clampAttempts(
			int attempts) {

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

		boolean verify(String otp);
	}

	// =========================================================
	// 攻撃結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String otp;

		private final int attemptCount;

		public AttackResult(
				boolean success,
				String otp,
				int attemptCount) {

			this.success =
					success;

			this.otp =
					otp;

			this.attemptCount =
					attemptCount;
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
	}
}