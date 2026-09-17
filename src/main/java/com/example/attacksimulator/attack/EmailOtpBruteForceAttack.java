package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

@Component
public class EmailOtpBruteForceAttack {

    /**
     * メールOTP総当たり攻撃を実行する。
     *
     * 今回の実験では、OTPを6桁の数字として扱う。
     * 正解OTPは999999とする。
     *
     * @param maxAttempts 最大試行回数
     * @return 攻撃結果
     */
    public AttackResult execute(int maxAttempts) {

        if (maxAttempts <= 0) {
            throw new IllegalArgumentException(
                    "最大試行回数は1以上にしてください。");
        }

        // 実験用の正解OTP
        String targetOtp = "999999";

        int attemptCount = 0;

        /*
         * 000000 ～ 999999 のOTPを順番に試行する。
         */
        for (int i = 0; i <= 999999; i++) {

            // 最大試行回数に到達したら終了
            if (attemptCount >= maxAttempts) {
                break;
            }

            String candidate =
                    String.format("%06d", i);

            attemptCount++;

            System.out.println(
                    "OTP Attempt "
                    + attemptCount
                    + " : candidate="
                    + candidate);

            // OTPが一致した場合
            if (candidate.equals(targetOtp)) {

                System.out.println("----------------------------------------");
                System.out.println("OTP found!");
                System.out.println("OTP = " + candidate);
                System.out.println(
                        "Attempts = " + attemptCount);
                System.out.println("----------------------------------------");

                return new AttackResult(
                        true,
                        candidate,
                        attemptCount);
            }
        }

        System.out.println("----------------------------------------");
        System.out.println("OTP not found.");
        System.out.println(
                "Attempts = " + attemptCount);
        System.out.println("----------------------------------------");

        return new AttackResult(
                false,
                null,
                attemptCount);
    }

    /**
     * メールOTP総当たり攻撃の結果
     */
    public static class AttackResult {

        private final boolean success;

        private final String otp;

        private final int attemptCount;

        public AttackResult(
                boolean success,
                String otp,
                int attemptCount) {

            this.success = success;
            this.otp = otp;
            this.attemptCount = attemptCount;
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
