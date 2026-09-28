package com.example.attacksimulator.attack;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class RandomPasswordAttack {

	// =========================================================
	// 定数
	// =========================================================

	/**
	 * 4桁Passwordの総組み合わせ数
	 *
	 * 0000 ～ 9999
	 */
	private static final int TOTAL_PASSWORD_COUNT =
			10_000;

	// =========================================================
	// PasswordEncoder
	// =========================================================

	private final PasswordEncoder passwordEncoder;

	/**
	 * 乱数生成器
	 */
	private final SecureRandom secureRandom;

	// =========================================================
	// コンストラクタ
	// =========================================================

	public RandomPasswordAttack(
			PasswordEncoder passwordEncoder) {

		this.passwordEncoder =
				passwordEncoder;

		this.secureRandom =
				new SecureRandom();
	}

	// =========================================================
	// ランダム攻撃
	// 既存互換用
	// =========================================================

	public AttackResult execute(
			String passwordHash) {

		return execute(
				passwordHash,
				TOTAL_PASSWORD_COUNT);
	}

	// =========================================================
	// ランダム攻撃
	// 最大試行回数指定
	// =========================================================

	public AttackResult execute(
			String passwordHash,
			int maxAttempts) {

		// =====================================================
		// 入力チェック
		// =====================================================

		if (passwordHash == null
				|| passwordHash.isBlank()) {

			throw new IllegalArgumentException(
					"パスワードハッシュが指定されていません。");
		}

		// =====================================================
		// 最大試行回数を制限
		// =====================================================

		int actualMaxAttempts =
				clampAttempts(
						maxAttempts);

		// =====================================================
		// 0000～9999を作成
		// =====================================================

		List<Integer> candidates =
				new ArrayList<>(
						TOTAL_PASSWORD_COUNT);

		for (int i = 0;
				i < TOTAL_PASSWORD_COUNT;
				i++) {

			candidates.add(i);
		}

		// =====================================================
		// 候補をランダムな順番に並べ替える
		// =====================================================

		Collections.shuffle(
				candidates,
				secureRandom);

		// =====================================================
		// ランダム攻撃開始
		// =====================================================

		int attemptCount = 0;

		System.out.println(
				"========================================");

		System.out.println(
				"ランダムPassword攻撃開始");

		System.out.println(
				"最大試行回数 = "
						+ actualMaxAttempts);

		System.out.println(
				"========================================");

		for (int i = 0;
				i < candidates.size();
				i++) {

			// -------------------------------------------------
			// 最大試行回数に到達
			// -------------------------------------------------

			if (attemptCount
					>= actualMaxAttempts) {

				break;
			}

			int candidateNumber =
					candidates.get(i);

			// -------------------------------------------------
			// 4桁に変換
			//
			// 1    → 0001
			// 42   → 0042
			// 1234 → 1234
			// -------------------------------------------------

			String candidate =
					String.format(
							"%04d",
							candidateNumber);

			// -------------------------------------------------
			// 試行回数を増やす
			// -------------------------------------------------

			attemptCount++;

			// -------------------------------------------------
			// 攻撃中の数字を表示
			// -------------------------------------------------

			System.out.println(
					"試行 "
							+ attemptCount
							+ " / "
							+ actualMaxAttempts
							+ " : "
							+ candidate);

			// -------------------------------------------------
			// BCrypt照合
			// -------------------------------------------------

			boolean matched =
					passwordEncoder.matches(
							candidate,
							passwordHash);

			// -------------------------------------------------
			// 突破成功
			// -------------------------------------------------

			if (matched) {

				System.out.println(
						"========================================");

				System.out.println(
						"一段階ランダム攻撃突破成功");

				System.out.println(
						"Password = "
								+ candidate);

				System.out.println(
						"試行回数 = "
								+ attemptCount);

				System.out.println(
						"========================================");

				return new AttackResult(
						true,
						candidate,
						attemptCount);
			}
		}

		// =====================================================
		// 最大試行回数到達
		// =====================================================

		System.out.println(
				"========================================");

		System.out.println(
				"一段階ランダム攻撃失敗");

		System.out.println(
				"試行回数 = "
						+ attemptCount);

		System.out.println(
				"========================================");

		return new AttackResult(
				false,
				null,
				attemptCount);
	}

	// =========================================================
	// 試行回数制限
	// =========================================================

	private int clampAttempts(
			int maxAttempts) {

		if (maxAttempts < 1) {

			return 1;
		}

		if (maxAttempts > TOTAL_PASSWORD_COUNT) {

			return TOTAL_PASSWORD_COUNT;
		}

		return maxAttempts;
	}

	// =========================================================
	// 攻撃結果
	// =========================================================

	public static class AttackResult {

		private final boolean success;

		private final String password;

		private final int attemptCount;

		public AttackResult(
				boolean success,
				String password,
				int attemptCount) {

			this.success =
					success;

			this.password =
					password;

			this.attemptCount =
					attemptCount;
		}

		// =====================================================
		// Getter
		// =====================================================

		public boolean isSuccess() {

			return success;
		}

		public String getPassword() {

			return password;
		}

		public int getAttemptCount() {

			return attemptCount;
		}
	}
}