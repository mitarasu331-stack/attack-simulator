package com.example.attacksimulator.service;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
import com.example.attacksimulator.attack.PasswordBruteForceAttack;

@Service
public class AttackService {

    private final PasswordBruteForceAttack passwordBruteForceAttack;

    private final MultiStagePasswordBruteForceAttack multiStagePasswordBruteForceAttack;

    private final EmailOtpBruteForceAttack emailOtpBruteForceAttack;

    public AttackService(
            PasswordBruteForceAttack passwordBruteForceAttack,
            MultiStagePasswordBruteForceAttack multiStagePasswordBruteForceAttack,
            EmailOtpBruteForceAttack emailOtpBruteForceAttack) {

        this.passwordBruteForceAttack =
                passwordBruteForceAttack;

        this.multiStagePasswordBruteForceAttack =
                multiStagePasswordBruteForceAttack;

        this.emailOtpBruteForceAttack =
                emailOtpBruteForceAttack;
    }

    /**
     * 従来のパスワード総当たり攻撃
     */
    public PasswordBruteForceAttack.AttackResult
            executePasswordBruteForce() {

        System.out.println("========================================");
        System.out.println("      Password Brute Force Attack");
        System.out.println("========================================");

        PasswordBruteForceAttack.AttackResult result =
                passwordBruteForceAttack.execute();

        System.out.println("----------------------------------------");
        System.out.println("Password brute force finished.");
        System.out.println("----------------------------------------");

        return result;
    }

    /**
     * 一段階認証
     *
     * ID + Password
     */
    public AttackResult executeOneStage() {

        System.out.println("========================================");
        System.out.println("       One Stage Authentication");
        System.out.println("========================================");

        AttackResult result =
                multiStagePasswordBruteForceAttack
                        .executeOneStage();

        System.out.println("----------------------------------------");
        System.out.println("One stage attack finished.");
        System.out.println("----------------------------------------");

        return result;
    }

    /**
     * 二段階認証
     *
     * ID + Password
     * ↓
     * Password2
     */
    public AttackResult executeTwoStage() {

        System.out.println("========================================");
        System.out.println("       Two Stage Authentication");
        System.out.println("========================================");

        AttackResult result =
                multiStagePasswordBruteForceAttack
                        .executeTwoStage();

        System.out.println("----------------------------------------");
        System.out.println("Two stage attack finished.");
        System.out.println("----------------------------------------");

        return result;
    }

    /**
     * 三段階認証
     *
     * ID + Password
     * ↓
     * Password2
     * ↓
     * Password3
     */
    public AttackResult executeThreeStage() {

        System.out.println("========================================");
        System.out.println("      Three Stage Authentication");
        System.out.println("========================================");

        AttackResult result =
                multiStagePasswordBruteForceAttack
                        .executeThreeStage();

        System.out.println("----------------------------------------");
        System.out.println("Three stage attack finished.");
        System.out.println("----------------------------------------");

        return result;
    }

    /**
     * メールOTP総当たり攻撃
     */
    public EmailOtpBruteForceAttack.AttackResult
            executeEmailOtpBruteForce(int maxAttempts) {

        System.out.println("========================================");
        System.out.println("       Email OTP Brute Force Attack");
        System.out.println("========================================");

        EmailOtpBruteForceAttack.AttackResult result =
                emailOtpBruteForceAttack.execute(
                        maxAttempts);

        System.out.println("----------------------------------------");
        System.out.println("Email OTP brute force finished.");
        System.out.println("----------------------------------------");

        return result;
    }
}