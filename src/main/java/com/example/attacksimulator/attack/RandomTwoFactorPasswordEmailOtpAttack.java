package com.example.attacksimulator.attack;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

import org.springframework.stereotype.Component;

@Component
public class RandomTwoFactorPasswordEmailOtpAttack {

	// =========================================================
	// 二要素認証
	// Password → Email OTP
	//
	// Passwordをランダムに試す
	// ↓
	// 正しいPasswordが見つかったらOTP攻撃へ
	// ↓
	// OTPをランダムに試す
	// =========================================================

	public AttackResult execute(
			int maxAttemptsPassword,
			int maxAttemptsOtp,
			PasswordVerifier passwordVerifier,
			OtpVerifier otpVerifier) {

		// =====================================================
		// 最大試行回数を調整
		// =====================================================

		if (maxAttemptsPassword < 1) {

			maxAttemptsPassword = 1;
		}

		if (maxAttemptsPassword > 10_000) {

			maxAttemptsPassword = 10_000;
		}

		if (maxAttemptsOtp < 1) {

			maxAttemptsOtp = 1;
		}

		if (maxAttemptsOtp > 1_000_000) {

			maxAttemptsOtp = 1_000_000;
		}

		// =====================================================
		// Password攻撃
		// 0000 ～ 9999を重複なしでランダムに試す
		// =====================================================

		Set<String> triedPasswords =
				new HashSet<>();

		int passwordAttemptCount = 0;

		String foundPassword = null;

		while (passwordAttemptCount
				< maxAttemptsPassword) {

			String candidatePassword =
					String.format(
							"%04d",
							ThreadLocalRandom.current()
							.nextInt(10_000));

			// -------------------------------------------------
			// すでに試したPasswordは除外
			// -------------------------------------------------

			if (!triedPasswords.add(
					candidatePassword)) {

				continue;
			}

			passwordAttemptCount++;

			// -------------------------------------------------
			// Password候補を1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					"ランダムPassword 試行 "
							+ passwordAttemptCount
							+ " / "
							+ maxAttemptsPassword
							+ " : "
							+ candidatePassword);

			boolean passwordSuccess =
					passwordVerifier.verify(
							candidatePassword);

			if (passwordSuccess) {

				foundPassword =
						candidatePassword;

				break;
			}
		}

		// =====================================================
		// Passwordが突破できなかった
		// =====================================================

		if (foundPassword == null) {

			return new AttackResult(
					false,
					null,
					null,
					passwordAttemptCount,
					0);
		}

		// =====================================================
		// Email OTP攻撃
		// 000000 ～ 999999を重複なしでランダムに試す
		// =====================================================

		Set<String> triedOtps =
				new HashSet<>();

		int otpAttemptCount = 0;

		String foundOtp = null;

		while (otpAttemptCount
				< maxAttemptsOtp) {

			String candidateOtp =
					String.format(
							"%06d",
							ThreadLocalRandom.current()
							.nextInt(1_000_000));

			// -------------------------------------------------
			// すでに試したOTPは除外
			// -------------------------------------------------

			if (!triedOtps.add(
					candidateOtp)) {

				continue;
			}

			otpAttemptCount++;

			// -------------------------------------------------
			// OTP候補を1件ずつ表示
			// -------------------------------------------------

			System.out.println(
					"ランダムOTP 試行 "
							+ otpAttemptCount
							+ " / "
							+ maxAttemptsOtp
							+ " : "
							+ candidateOtp);

			boolean otpSuccess =
					otpVerifier.verify(
							candidateOtp);

			if (otpSuccess) {

				foundOtp =
						candidateOtp;

				break;
			}
		}

		// =====================================================
		// 二要素認証成功
		// =====================================================

		if (foundOtp != null) {

			return new AttackResult(
					true,
					foundPassword,
					foundOtp,
					passwordAttemptCount,
					otpAttemptCount);
		}

		// =====================================================
		// OTPが突破できなかった
		// =====================================================

		return new AttackResult(
				false,
				null,
				null,
				passwordAttemptCount,
				otpAttemptCount);
	}

	// =========================================================
	// Password確認用
	// =========================================================

	@FunctionalInterface
	public interface PasswordVerifier {

		boolean verify(
				String password);
	}

	// =========================================================
	// OTP確認用
	// =========================================================

	@FunctionalInterface
	public interface OtpVerifier {

		boolean verify(
				String otp);
	}

	// =========================================================
	// 攻撃結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String password;

		private final String otp;

		private final int passwordAttemptCount;

		private final int otpAttemptCount;

		public AttackResult(
				boolean success,
				String password,
				String otp,
				int passwordAttemptCount,
				int otpAttemptCount) {

			this.success =
					success;

			this.password =
					password;

			this.otp =
					otp;

			this.passwordAttemptCount =
					passwordAttemptCount;

			this.otpAttemptCount =
					otpAttemptCount;
		}

		// =====================================================
		// 攻撃成功
		// =====================================================

		public boolean isSuccess() {

			return success;
		}

		// =====================================================
		// 発見したPassword
		// =====================================================

		public String getPassword() {

			return password;
		}

		// =====================================================
		// 発見したOTP
		// =====================================================

		public String getOtp() {

			return otp;
		}

		// =====================================================
		// Password試行回数
		// =====================================================

		public int getPasswordAttemptCount() {

			return passwordAttemptCount;
		}

		// =====================================================
		// OTP試行回数
		// =====================================================

		public int getOtpAttemptCount() {

			return otpAttemptCount;
		}

		// =====================================================
		// 総試行回数
		//
		// Passwordの試行回数
		// +
		// OTPの試行回数
		// =====================================================

		public int getAttemptCount() {

			return passwordAttemptCount
					+ otpAttemptCount;
		}
	}
}