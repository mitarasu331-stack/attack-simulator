package com.example.attacksimulator.service;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
import com.example.attacksimulator.attack.PasswordBruteForceAttack;

@Service
public class AttackService {

    private final PasswordBruteForceAttack
            passwordBruteForceAttack;

    private final MultiStagePasswordBruteForceAttack
            multiStagePasswordBruteForceAttack;

    private final EmailOtpBruteForceAttack
            emailOtpBruteForceAttack;

    private final FactorAuthenticationAttack
            factorAuthenticationAttack;

    public AttackService(
            PasswordBruteForceAttack passwordBruteForceAttack,
            MultiStagePasswordBruteForceAttack multiStagePasswordBruteForceAttack,
            EmailOtpBruteForceAttack emailOtpBruteForceAttack,
            FactorAuthenticationAttack factorAuthenticationAttack) {

        this.passwordBruteForceAttack =
                passwordBruteForceAttack;

        this.multiStagePasswordBruteForceAttack =
                multiStagePasswordBruteForceAttack;

        this.emailOtpBruteForceAttack =
                emailOtpBruteForceAttack;

        this.factorAuthenticationAttack =
                factorAuthenticationAttack;
    }

    /**
     * 一段階認証
     *
     * ID + Password
     *
     * 認証操作回数：3回
     */
    public AttackResult executeOneStage() {

        return multiStagePasswordBruteForceAttack
                .executeOneStage();
    }

    /**
     * 二段階認証
     *
     * ID + Password → Password2
     *
     * 認証操作回数：5回
     */
    public AttackResult executeTwoStage() {

        return multiStagePasswordBruteForceAttack
                .executeTwoStage();
    }

    /**
     * 三段階認証
     *
     * ID + Password → Password2 → Password3
     *
     * 認証操作回数：7回
     */
    public AttackResult executeThreeStage() {

        return multiStagePasswordBruteForceAttack
                .executeThreeStage();
    }

    /**
     * メールOTP総当たり攻撃
     *
     * ※既存処理との互換性のため残している。
     * 最終的な認証方式の選択では使用しない。
     */
    public EmailOtpBruteForceAttack.AttackResult
    executeEmailOtpBruteForce(
            int maxAttempts) {

        return emailOtpBruteForceAttack
                .execute(maxAttempts);
    }

    /**
     * 従来の4桁パスワード総当たり攻撃
     *
     * ※既存処理との互換性のため残している。
     */
    public PasswordBruteForceAttack.AttackResult
    executePasswordBruteForce() {

        return passwordBruteForceAttack
                .execute();
    }

    /**
     * 一要素認証（Password）
     *
     * ID + Password
     *
     * 認証操作回数：3回
     */
    public FactorAuthenticationAttack.FactorAttackResult
    executeOneFactorPassword() {

        return factorAuthenticationAttack
                .executeOneFactorPassword();
    }

    /**
     * 一要素認証（Email OTP）
     *
     * ID + Email OTP
     *
     * 認証操作回数：3回
     */
    public FactorAuthenticationAttack.FactorAttackResult
    executeOneFactorEmailOtp(
            int maxAttempts) {

        return factorAuthenticationAttack
                .executeOneFactorEmailOtp(
                        maxAttempts);
    }

    /**
     * 二要素認証
     *
     * ID + Password → Email OTP
     *
     * 認証操作回数：5回
     */
    public FactorAuthenticationAttack.FactorAttackResult
    executeTwoFactorPasswordEmailOtp(
            int maxOtpAttempts) {

        return factorAuthenticationAttack
                .executeTwoFactorPasswordEmailOtp(
                        maxOtpAttempts);
    }
}