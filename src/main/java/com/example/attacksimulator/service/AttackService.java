package com.example.attacksimulator.service;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
import com.example.attacksimulator.attack.PasswordBruteForceAttack;
import com.example.attacksimulator.model.NewAuthLabUser;
import com.example.attacksimulator.repository.NewAuthLabUserRepository;

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

    private final NewAuthLabUserRepository
            newAuthLabUserRepository;

    public AttackService(
            PasswordBruteForceAttack passwordBruteForceAttack,
            MultiStagePasswordBruteForceAttack multiStagePasswordBruteForceAttack,
            EmailOtpBruteForceAttack emailOtpBruteForceAttack,
            FactorAuthenticationAttack factorAuthenticationAttack,
            NewAuthLabUserRepository newAuthLabUserRepository) {

        this.passwordBruteForceAttack =
                passwordBruteForceAttack;

        this.multiStagePasswordBruteForceAttack =
                multiStagePasswordBruteForceAttack;

        this.emailOtpBruteForceAttack =
                emailOtpBruteForceAttack;

        this.factorAuthenticationAttack =
                factorAuthenticationAttack;

        this.newAuthLabUserRepository =
                newAuthLabUserRepository;
    }

    // =========================================================
    // 対象ユーザー取得
    // =========================================================

    private NewAuthLabUser getUser(
            String username) {

        return newAuthLabUserRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "指定されたユーザーが見つかりません: "
                                + username));
    }

    // =========================================================
    // 一段階認証
    // ID + Password
    // =========================================================

    public AttackResult executeOneStage(
            String username) {

        NewAuthLabUser user =
                getUser(username);

        return multiStagePasswordBruteForceAttack
                .executeOneStage(
                        user.getPassword());
    }

    // =========================================================
    // 二段階認証
    // Password → Password2
    // =========================================================

    public AttackResult executeTwoStage(
            String username) {

        NewAuthLabUser user =
                getUser(username);

        return multiStagePasswordBruteForceAttack
                .executeTwoStage(
                        user.getPassword(),
                        user.getPassword2());
    }

    // =========================================================
    // 三段階認証
    // Password → Password2 → Password3
    // =========================================================

    public AttackResult executeThreeStage(
            String username) {

        NewAuthLabUser user =
                getUser(username);

        return multiStagePasswordBruteForceAttack
                .executeThreeStage(
                        user.getPassword(),
                        user.getPassword2(),
                        user.getPassword3());
    }

    // =========================================================
    // Password総当たり
    // =========================================================

    public PasswordBruteForceAttack.AttackResult
    executePasswordBruteForce(
            String username) {

        NewAuthLabUser user =
                getUser(username);

        return passwordBruteForceAttack
                .execute(
                        user.getPassword());
    }

    // =========================================================
    // Email OTP総当たり
    // =========================================================

    public EmailOtpBruteForceAttack.AttackResult
    executeEmailOtpBruteForce(
            int maxAttempts) {

        return emailOtpBruteForceAttack
                .execute(maxAttempts);
    }

    // =========================================================
    // 一要素認証 Password
    // =========================================================

    public FactorAuthenticationAttack.FactorAttackResult
    executeOneFactorPassword(
            String username) {

        NewAuthLabUser user =
                getUser(username);

        return factorAuthenticationAttack
                .executeOneFactorPassword(
                        user.getPassword());
    }

    // =========================================================
    // 一要素認証 Email OTP
    // =========================================================

    public FactorAuthenticationAttack.FactorAttackResult
    executeOneFactorEmailOtp(
            int maxAttempts) {

        return factorAuthenticationAttack
                .executeOneFactorEmailOtp(
                        maxAttempts);
    }

    // =========================================================
    // 二要素認証
    // Password → Email OTP
    // =========================================================

    public FactorAuthenticationAttack.FactorAttackResult
    executeTwoFactorPasswordEmailOtp(
            String username,
            int maxOtpAttempts) {

        NewAuthLabUser user =
                getUser(username);

        return factorAuthenticationAttack
                .executeTwoFactorPasswordEmailOtp(
                        user.getPassword(),
                        maxOtpAttempts);
    }
}