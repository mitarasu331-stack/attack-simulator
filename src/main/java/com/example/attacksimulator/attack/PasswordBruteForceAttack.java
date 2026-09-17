package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

@Component
public class PasswordBruteForceAttack {

    /**
     * 4桁数字パスワードの候補を生成する。
     *
     * @param number 0～9999
     * @return 4桁の数字文字列
     */
    public String generateCandidate(int number) {

        if (number < 0 || number > 9999) {
            throw new IllegalArgumentException(
                    "4桁パスワードの範囲は0000～9999です。");
        }

        return String.format("%04d", number);
    }

    /**
     * パスワード総当たり攻撃を実行する。
     *
     * 実験用の正解パスワードは9999。
     *
     * @return 攻撃結果
     */
    public AttackResult execute() {

        String targetPassword = "9999";

        int attemptCount = 0;

        for (int i = 0; i <= 9999; i++) {

            String candidate = generateCandidate(i);

            attemptCount = i + 1;

            System.out.println(
                    "Attempt "
                    + attemptCount
                    + " : candidate="
                    + candidate);

            if (candidate.equals(targetPassword)) {

                System.out.println("----------------------------------------");
                System.out.println("Password found!");
                System.out.println("Password = " + candidate);
                System.out.println(
                        "Attempts = " + attemptCount);
                System.out.println("----------------------------------------");

                return new AttackResult(
                        true,
                        candidate,
                        attemptCount);
            }
        }

        return new AttackResult(
                false,
                null,
                attemptCount);
    }

    /**
     * パスワード総当たり攻撃の結果
     */
    public static class AttackResult {

        private final boolean success;

        private final String password;

        private final int attemptCount;

        public AttackResult(
                boolean success,
                String password,
                int attemptCount) {

            this.success = success;
            this.password = password;
            this.attemptCount = attemptCount;
        }

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