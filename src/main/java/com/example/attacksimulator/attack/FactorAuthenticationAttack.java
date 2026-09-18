package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

@Component
public class FactorAuthenticationAttack {

    private final PasswordBruteForceAttack
            passwordBruteForceAttack;

    private final EmailOtpBruteForceAttack
            emailOtpBruteForceAttack;

    public FactorAuthenticationAttack(
            PasswordBruteForceAttack passwordBruteForceAttack,
            EmailOtpBruteForceAttack emailOtpBruteForceAttack) {

        this.passwordBruteForceAttack =
                passwordBruteForceAttack;

        this.emailOtpBruteForceAttack =
                emailOtpBruteForceAttack;
    }

    /**
     * 一要素認証（Password）
     *
     * 認証構成：
     * ID + Password
     *
     * 認証操作回数：3回
     *
     * @param passwordHash
     *        DBに保存されているPasswordのBCryptハッシュ
     */
    public FactorAttackResult
    executeOneFactorPassword(
            String passwordHash) {

        PasswordBruteForceAttack.AttackResult
                result =
                passwordBruteForceAttack
                        .execute(passwordHash);

        return new FactorAttackResult(
                "one-factor-password",
                "ID + Password",
                3,
                result.isSuccess(),
                result.getPassword(),
                null,
                result.getAttemptCount());
    }

    /**
     * 一要素認証（Email OTP）
     *
     * 認証構成：
     * ID + Email OTP
     *
     * 認証操作回数：3回
     */
    public FactorAttackResult
    executeOneFactorEmailOtp(
            int maxAttempts) {

        EmailOtpBruteForceAttack.AttackResult
                result =
                emailOtpBruteForceAttack
                        .execute(maxAttempts);

        return new FactorAttackResult(
                "one-factor-email-otp",
                "ID + Email OTP",
                3,
                result.isSuccess(),
                null,
                result.getOtp(),
                result.getAttemptCount());
    }

    /**
     * 二要素認証
     *
     * 認証構成：
     * ID + Password → Email OTP
     *
     * 認証操作回数：5回
     *
     * @param passwordHash
     *        DBに保存されているPasswordのBCryptハッシュ
     *
     * @param maxOtpAttempts
     *        Email OTPの最大試行回数
     */
    public FactorAttackResult
    executeTwoFactorPasswordEmailOtp(
            String passwordHash,
            int maxOtpAttempts) {

        /*
         * 第1要素：
         * ID + Password
         *
         * DBから取得したBCryptハッシュに対して
         * Password総当たりを実行する。
         */
        PasswordBruteForceAttack.AttackResult
                passwordResult =
                passwordBruteForceAttack
                        .execute(passwordHash);

        /*
         * Passwordを突破できなかった場合、
         * Email OTPには進まない。
         */
        if (!passwordResult.isSuccess()) {

            return new FactorAttackResult(
                    "two-factor-password-email-otp",
                    "ID + Password → Email OTP",
                    5,
                    false,
                    passwordResult.getPassword(),
                    null,
                    passwordResult.getAttemptCount());
        }

        /*
         * 第2要素：
         * Email OTP
         */
        EmailOtpBruteForceAttack.AttackResult
                otpResult =
                emailOtpBruteForceAttack
                        .execute(maxOtpAttempts);

        /*
         * PasswordとEmail OTPの
         * 攻撃試行回数を合計する。
         */
        int totalAttemptCount =
                passwordResult.getAttemptCount()
                + otpResult.getAttemptCount();

        /*
         * PasswordとEmail OTPの
         * 両方に成功した場合のみ突破成功。
         */
        return new FactorAttackResult(
                "two-factor-password-email-otp",
                "ID + Password → Email OTP",
                5,
                otpResult.isSuccess(),
                passwordResult.getPassword(),
                otpResult.getOtp(),
                totalAttemptCount);
    }

    /**
     * 認証要素攻撃の結果
     */
    public static class FactorAttackResult {

        private final String authMethod;

        private final String
                authenticationConfiguration;

        private final int operationCount;

        private final boolean success;

        private final String password;

        private final String otp;

        private final int attemptCount;

        public FactorAttackResult(
                String authMethod,
                String authenticationConfiguration,
                int operationCount,
                boolean success,
                String password,
                String otp,
                int attemptCount) {

            this.authMethod =
                    authMethod;

            this.authenticationConfiguration =
                    authenticationConfiguration;

            this.operationCount =
                    operationCount;

            this.success =
                    success;

            this.password =
                    password;

            this.otp =
                    otp;

            this.attemptCount =
                    attemptCount;
        }

        public String getAuthMethod() {

            return authMethod;
        }

        public String
        getAuthenticationConfiguration() {

            return authenticationConfiguration;
        }

        public int getOperationCount() {

            return operationCount;
        }

        public boolean isSuccess() {

            return success;
        }

        public String getPassword() {

            return password;
        }

        public String getOtp() {

            return otp;
        }

        public int getAttemptCount() {

            return attemptCount;
        }
    }
}