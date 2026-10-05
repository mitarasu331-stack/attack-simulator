package com.example.attacksimulator.service;

public final class AttackConsoleLogger {

    private static final String SEPARATOR =
            "========================================";

    private AttackConsoleLogger() {
    }

    /**
     * 攻撃開始ログ
     */
    public static void start(
            String attackName,
            String username,
            int maxAttempts) {

        System.out.println();
        System.out.println(SEPARATOR);
        System.out.println(attackName + "開始");
        System.out.println("username = " + username);
        System.out.println("最大試行回数 = " + maxAttempts);
        System.out.println(SEPARATOR);
    }

    /**
     * 試行回数の進捗ログ
     */
    public static void progress(
            String attackName,
            int attempts,
            int maxAttempts) {

        System.out.println(
                attackName + " 試行回数 = "
                + attempts + " / " + maxAttempts);
    }

    /**
     * 攻撃結果ログ
     */
    public static void result(
            String attackName,
            String username,
            String credential,
            int maxAttempts,
            int actualAttempts,
            boolean attackSuccess,
            boolean realLoginSuccess,
            String finalUrl,
            long attackTimeMs) {

        System.out.println();
        System.out.println("===== " + attackName + "結果 =====");
        System.out.println("username = " + username);
        System.out.println("認証情報 = "
                + (credential == null ? "未取得" : credential));
        System.out.println("最大試行回数 = " + maxAttempts);
        System.out.println("実攻撃試行回数 = " + actualAttempts);
        System.out.println("ランダム攻撃成功 = " + attackSuccess);
        System.out.println("実ログイン成功 = " + realLoginSuccess);
        System.out.println("Final URL = " + finalUrl);
        System.out.println("攻撃時間 = " + attackTimeMs + " ms");
        System.out.println(SEPARATOR);
    }
}