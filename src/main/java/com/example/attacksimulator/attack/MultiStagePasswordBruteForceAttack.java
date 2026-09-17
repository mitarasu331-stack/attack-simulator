package com.example.attacksimulator.attack;

import org.springframework.stereotype.Component;

@Component
public class MultiStagePasswordBruteForceAttack {

/**
 * 4桁数字パスワードの候補を生成する。
 */
private String generateCandidate(int number) {

    if (number < 0 || number > 9999) {

        throw new IllegalArgumentException(
                "4桁パスワードの範囲は0000～9999です。");
    }

    return String.format("%04d", number);
}

/**
 * 一段階認証の総当たり攻撃。
 *
 * ID + Password
 */
public AttackResult executeOneStage() {

    String targetPassword = "9999";

    for (int i = 0; i <= 9999; i++) {

        String candidate = generateCandidate(i);

        int attemptCount = i + 1;

        System.out.println(
                "Stage 1 - Attempt "
                + attemptCount
                + " : password="
                + candidate);

        if (candidate.equals(targetPassword)) {

            System.out.println(
                    "Stage 1 password found: "
                    + candidate);

            return new AttackResult(
                    "one-stage",
                    true,
                    1,
                    attemptCount,
                    candidate,
                    null,
                    null);
        }
    }

    return new AttackResult(
            "one-stage",
            false,
            1,
            10000,
            null,
            null,
            null);
}

/**
 * 二段階認証の総当たり攻撃。
 *
 * ID + Password
 * ↓
 * Password2
 */
public AttackResult executeTwoStage() {

    String targetPassword = "9999";
    String targetPassword2 = "9999";

    int totalAttempts = 0;

    // 第1段階
    for (int i = 0; i <= 9999; i++) {

        String candidate = generateCandidate(i);

        totalAttempts++;

        System.out.println(
                "Stage 1 - Attempt "
                + (i + 1)
                + " : password="
                + candidate);

        if (candidate.equals(targetPassword)) {

            System.out.println(
                    "Stage 1 password found: "
                    + candidate);

            break;
        }
    }

    // 第2段階
    for (int i = 0; i <= 9999; i++) {

        String candidate = generateCandidate(i);

        totalAttempts++;

        System.out.println(
                "Stage 2 - Attempt "
                + (i + 1)
                + " : password2="
                + candidate);

        if (candidate.equals(targetPassword2)) {

            System.out.println(
                    "Stage 2 password found: "
                    + candidate);

            return new AttackResult(
                    "two-stage",
                    true,
                    2,
                    totalAttempts,
                    targetPassword,
                    candidate,
                    null);
        }
    }

    return new AttackResult(
            "two-stage",
            false,
            2,
            totalAttempts,
            targetPassword,
            null,
            null);
}

/**
 * 三段階認証の総当たり攻撃。
 *
 * ID + Password
 * ↓
 * Password2
 * ↓
 * Password3
 */
public AttackResult executeThreeStage() {

    String targetPassword = "9999";
    String targetPassword2 = "9999";
    String targetPassword3 = "9999";

    int totalAttempts = 0;

    // 第1段階
    for (int i = 0; i <= 9999; i++) {

        String candidate = generateCandidate(i);

        totalAttempts++;

        System.out.println(
                "Stage 1 - Attempt "
                + (i + 1)
                + " : password="
                + candidate);

        if (candidate.equals(targetPassword)) {

            System.out.println(
                    "Stage 1 password found: "
                    + candidate);

            break;
        }
    }

    // 第2段階
    for (int i = 0; i <= 9999; i++) {

        String candidate = generateCandidate(i);

        totalAttempts++;

        System.out.println(
                "Stage 2 - Attempt "
                + (i + 1)
                + " : password2="
                + candidate);

        if (candidate.equals(targetPassword2)) {

            System.out.println(
                    "Stage 2 password found: "
                    + candidate);

            break;
        }
    }

    // 第3段階
    for (int i = 0; i <= 9999; i++) {

        String candidate = generateCandidate(i);

        totalAttempts++;

        System.out.println(
                "Stage 3 - Attempt "
                + (i + 1)
                + " : password3="
                + candidate);

        if (candidate.equals(targetPassword3)) {

            System.out.println(
                    "Stage 3 password found: "
                    + candidate);

            return new AttackResult(
                    "three-stage",
                    true,
                    3,
                    totalAttempts,
                    targetPassword,
                    targetPassword2,
                    candidate);
        }
    }

    return new AttackResult(
            "three-stage",
            false,
            3,
            totalAttempts,
            targetPassword,
            targetPassword2,
            null);
}

/**
 * 攻撃結果
 */
public static class AttackResult {

    private final String authMethod;

    private final boolean success;

    private final int stageCount;

    private final int totalAttempts;

    private final String password;

    private final String password2;

    private final String password3;

    public AttackResult(
            String authMethod,
            boolean success,
            int stageCount,
            int totalAttempts,
            String password,
            String password2,
            String password3) {

        this.authMethod = authMethod;
        this.success = success;
        this.stageCount = stageCount;
        this.totalAttempts = totalAttempts;
        this.password = password;
        this.password2 = password2;
        this.password3 = password3;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public boolean isSuccess() {
        return success;
    }

    public int getStageCount() {
        return stageCount;
    }

    public int getTotalAttempts() {
        return totalAttempts;
    }

    public String getPassword() {
        return password;
    }

    public String getPassword2() {
        return password2;
    }

    public String getPassword3() {
        return password3;
    }
}

}
