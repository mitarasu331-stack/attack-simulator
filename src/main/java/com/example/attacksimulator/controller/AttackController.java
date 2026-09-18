package com.example.attacksimulator.controller;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.attacksimulator.attack.FactorAuthenticationAttack.FactorAttackResult;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
import com.example.attacksimulator.model.ExperimentResult;
import com.example.attacksimulator.service.AttackService;
import com.example.attacksimulator.service.ExperimentResultService;

@Controller
public class AttackController {

    private final AttackService attackService;

    private final ExperimentResultService
            experimentResultService;

    public AttackController(
            AttackService attackService,
            ExperimentResultService experimentResultService) {

        this.attackService =
                attackService;

        this.experimentResultService =
                experimentResultService;
    }

    /**
     * 攻撃実験画面
     */
    @GetMapping("/")
    public String index() {

        return "attack";
    }

    /**
     * 一段階・二段階・三段階認証
     *
     * ID + Password
     * ID + Password → Password2
     * ID + Password → Password2 → Password3
     */
    @PostMapping("/attack/password")
    public String passwordBruteForce(
            @RequestParam(defaultValue = "one-stage")
            String authMethod,

            @RequestParam(
                    name = "username",
                    required = false)
            String username,

            Model model) {

        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        long startTime =
                System.nanoTime();

        AttackResult result;

        switch (authMethod) {

            case "one-stage":

                result =
                        attackService
                                .executeOneStage();

                break;

            case "two-stage":

                result =
                        attackService
                                .executeTwoStage();

                break;

            case "three-stage":

                result =
                        attackService
                                .executeThreeStage();

                break;

            default:

                throw new IllegalArgumentException(
                        "不正な認証方式です: "
                        + authMethod);
        }

        long endTime =
                System.nanoTime();

        long attackTimeMs =
                (endTime - startTime)
                / 1_000_000;

        int operationCount;

        int maxAttemptCount;

        String authenticationConfiguration;

        switch (authMethod) {

            case "one-stage":

                operationCount = 3;

                maxAttemptCount = 10000;

                authenticationConfiguration =
                        "ID + Password";

                break;

            case "two-stage":

                operationCount = 5;

                maxAttemptCount = 20000;

                authenticationConfiguration =
                        "ID + Password → Password2";

                break;

            case "three-stage":

                operationCount = 7;

                maxAttemptCount = 30000;

                authenticationConfiguration =
                        "ID + Password → Password2 → Password3";

                break;

            default:

                operationCount = 0;

                maxAttemptCount = 0;

                authenticationConfiguration =
                        "不明";
        }

        int experimentNumber =
                experimentResultService
                        .getResultCount() + 1;

        String credential =
                createPasswordCredential(result);

        ExperimentResult experimentResult =
                new ExperimentResult(
                        experimentNumber,
                        authMethod,
                        operationCount,
                        authenticationConfiguration,
                        maxAttemptCount,
                        result.getTotalAttempts(),
                        result.isSuccess(),
                        credential,
                        attackTimeMs,
                        experimentDateTime);

        experimentResultService.addResult(
                experimentResult);

        /*
         * 結果画面へ渡す値
         */
        model.addAttribute(
                "experimentNumber",
                experimentNumber);

        model.addAttribute(
                "username",
                username);

        model.addAttribute(
                "authMethod",
                authMethod);

        model.addAttribute(
                "success",
                result.isSuccess());

        model.addAttribute(
                "stageCount",
                result.getStageCount());

        model.addAttribute(
                "attemptCount",
                result.getTotalAttempts());

        model.addAttribute(
                "password",
                result.getPassword());

        model.addAttribute(
                "password2",
                result.getPassword2());

        model.addAttribute(
                "password3",
                result.getPassword3());

        model.addAttribute(
                "otp",
                null);

        model.addAttribute(
                "attackTimeMs",
                attackTimeMs);

        model.addAttribute(
                "experimentDateTime",
                experimentDateTime);

        model.addAttribute(
                "maxAttemptCount",
                maxAttemptCount);

        model.addAttribute(
                "authenticationConfiguration",
                authenticationConfiguration);

        model.addAttribute(
                "operationCount",
                operationCount);

        return "result";
    }

    /**
     * 一要素認証・二要素認証
     *
     * 一要素（Password）
     * 一要素（Email OTP）
     * 二要素（Password + Email OTP）
     */
    @PostMapping("/attack/factor")
    public String factorAuthentication(
            @RequestParam
            String authMethod,

            @RequestParam(
                    name = "username",
                    required = false)
            String username,

            @RequestParam(
                    name = "maxAttempts",
                    defaultValue = "10000")
            int maxAttempts,

            Model model) {

        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        long startTime =
                System.nanoTime();

        FactorAttackResult result;

        switch (authMethod) {

            case "one-factor-password":

                result =
                        attackService
                                .executeOneFactorPassword();

                break;

            case "one-factor-email-otp":

                result =
                        attackService
                                .executeOneFactorEmailOtp(
                                        maxAttempts);

                break;

            case "two-factor-password-email-otp":

                result =
                        attackService
                                .executeTwoFactorPasswordEmailOtp(
                                        maxAttempts);

                break;

            default:

                throw new IllegalArgumentException(
                        "不正な認証方式です: "
                        + authMethod);
        }

        long endTime =
                System.nanoTime();

        long attackTimeMs =
                (endTime - startTime)
                / 1_000_000;

        int experimentNumber =
                experimentResultService
                        .getResultCount() + 1;

        int operationCount =
                result.getOperationCount();

        int maxAttemptCount;

        if (authMethod.equals(
                "one-factor-password")) {

            maxAttemptCount = 10000;

        } else {

            maxAttemptCount = maxAttempts;
        }

        ExperimentResult experimentResult =
                new ExperimentResult(
                        experimentNumber,
                        authMethod,
                        operationCount,
                        result.getAuthenticationConfiguration(),
                        maxAttemptCount,
                        result.getAttemptCount(),
                        result.isSuccess(),
                        createFactorCredential(result),
                        attackTimeMs,
                        experimentDateTime);

        experimentResultService.addResult(
                experimentResult);

        /*
         * 結果画面へ渡す値
         */
        model.addAttribute(
                "experimentNumber",
                experimentNumber);

        model.addAttribute(
                "username",
                username);

        model.addAttribute(
                "authMethod",
                authMethod);

        model.addAttribute(
                "success",
                result.isSuccess());

        model.addAttribute(
                "stageCount",
                null);

        model.addAttribute(
                "attemptCount",
                result.getAttemptCount());

        model.addAttribute(
                "password",
                result.getPassword());

        model.addAttribute(
                "password2",
                null);

        model.addAttribute(
                "password3",
                null);

        model.addAttribute(
                "otp",
                result.getOtp());

        model.addAttribute(
                "attackTimeMs",
                attackTimeMs);

        model.addAttribute(
                "experimentDateTime",
                experimentDateTime);

        model.addAttribute(
                "maxAttemptCount",
                maxAttemptCount);

        model.addAttribute(
                "authenticationConfiguration",
                result.getAuthenticationConfiguration());

        model.addAttribute(
                "operationCount",
                operationCount);

        return "result";
    }

    /**
     * 実験結果一覧
     */
    @GetMapping("/results")
    public String results(Model model) {

        model.addAttribute(
                "results",
                experimentResultService.getResults());

        /*
         * 一段階認証
         */
        model.addAttribute(
                "oneStageExperimentCount",
                experimentResultService
                        .getExperimentCountByAuthMethod(
                                "one-stage"));

        model.addAttribute(
                "oneStageSuccessCount",
                experimentResultService
                        .getSuccessCountByAuthMethod(
                                "one-stage"));

        model.addAttribute(
                "oneStageSuccessRate",
                experimentResultService
                        .getSuccessRateByAuthMethod(
                                "one-stage"));

        model.addAttribute(
                "oneStageAverageAttemptCount",
                experimentResultService
                        .getAverageAttemptCountByAuthMethod(
                                "one-stage"));

        model.addAttribute(
                "oneStageSuccessAttackTimeTotal",
                experimentResultService
                        .getSuccessAttackTimeTotalByAuthMethod(
                                "one-stage"));

        model.addAttribute(
                "oneStageAverageSuccessAttackTime",
                experimentResultService
                        .getAverageSuccessAttackTimeByAuthMethod(
                                "one-stage"));

        /*
         * 二段階認証
         */
        model.addAttribute(
                "twoStageExperimentCount",
                experimentResultService
                        .getExperimentCountByAuthMethod(
                                "two-stage"));

        model.addAttribute(
                "twoStageSuccessCount",
                experimentResultService
                        .getSuccessCountByAuthMethod(
                                "two-stage"));

        model.addAttribute(
                "twoStageSuccessRate",
                experimentResultService
                        .getSuccessRateByAuthMethod(
                                "two-stage"));

        model.addAttribute(
                "twoStageAverageAttemptCount",
                experimentResultService
                        .getAverageAttemptCountByAuthMethod(
                                "two-stage"));

        model.addAttribute(
                "twoStageSuccessAttackTimeTotal",
                experimentResultService
                        .getSuccessAttackTimeTotalByAuthMethod(
                                "two-stage"));

        model.addAttribute(
                "twoStageAverageSuccessAttackTime",
                experimentResultService
                        .getAverageSuccessAttackTimeByAuthMethod(
                                "two-stage"));

        /*
         * 三段階認証
         */
        model.addAttribute(
                "threeStageExperimentCount",
                experimentResultService
                        .getExperimentCountByAuthMethod(
                                "three-stage"));

        model.addAttribute(
                "threeStageSuccessCount",
                experimentResultService
                        .getSuccessCountByAuthMethod(
                                "three-stage"));

        model.addAttribute(
                "threeStageSuccessRate",
                experimentResultService
                        .getSuccessRateByAuthMethod(
                                "three-stage"));

        model.addAttribute(
                "threeStageAverageAttemptCount",
                experimentResultService
                        .getAverageAttemptCountByAuthMethod(
                                "three-stage"));

        model.addAttribute(
                "threeStageSuccessAttackTimeTotal",
                experimentResultService
                        .getSuccessAttackTimeTotalByAuthMethod(
                                "three-stage"));

        model.addAttribute(
                "threeStageAverageSuccessAttackTime",
                experimentResultService
                        .getAverageSuccessAttackTimeByAuthMethod(
                                "three-stage"));

        /*
         * 一要素認証（Password）
         */
        model.addAttribute(
                "oneFactorPasswordExperimentCount",
                experimentResultService
                        .getExperimentCountByAuthMethod(
                                "one-factor-password"));

        model.addAttribute(
                "oneFactorPasswordSuccessCount",
                experimentResultService
                        .getSuccessCountByAuthMethod(
                                "one-factor-password"));

        model.addAttribute(
                "oneFactorPasswordSuccessRate",
                experimentResultService
                        .getSuccessRateByAuthMethod(
                                "one-factor-password"));

        model.addAttribute(
                "oneFactorPasswordAverageAttemptCount",
                experimentResultService
                        .getAverageAttemptCountByAuthMethod(
                                "one-factor-password"));

        model.addAttribute(
                "oneFactorPasswordSuccessAttackTimeTotal",
                experimentResultService
                        .getSuccessAttackTimeTotalByAuthMethod(
                                "one-factor-password"));

        model.addAttribute(
                "oneFactorPasswordAverageSuccessAttackTime",
                experimentResultService
                        .getAverageSuccessAttackTimeByAuthMethod(
                                "one-factor-password"));

        /*
         * 一要素認証（Email OTP）
         */
        model.addAttribute(
                "oneFactorEmailOtpExperimentCount",
                experimentResultService
                        .getExperimentCountByAuthMethod(
                                "one-factor-email-otp"));

        model.addAttribute(
                "oneFactorEmailOtpSuccessCount",
                experimentResultService
                        .getSuccessCountByAuthMethod(
                                "one-factor-email-otp"));

        model.addAttribute(
                "oneFactorEmailOtpSuccessRate",
                experimentResultService
                        .getSuccessRateByAuthMethod(
                                "one-factor-email-otp"));

        model.addAttribute(
                "oneFactorEmailOtpAverageAttemptCount",
                experimentResultService
                        .getAverageAttemptCountByAuthMethod(
                                "one-factor-email-otp"));

        model.addAttribute(
                "oneFactorEmailOtpSuccessAttackTimeTotal",
                experimentResultService
                        .getSuccessAttackTimeTotalByAuthMethod(
                                "one-factor-email-otp"));

        model.addAttribute(
                "oneFactorEmailOtpAverageSuccessAttackTime",
                experimentResultService
                        .getAverageSuccessAttackTimeByAuthMethod(
                                "one-factor-email-otp"));

        /*
         * 二要素認証
         *
         * Password + Email OTP
         */
        model.addAttribute(
                "twoFactorPasswordEmailOtpExperimentCount",
                experimentResultService
                        .getExperimentCountByAuthMethod(
                                "two-factor-password-email-otp"));

        model.addAttribute(
                "twoFactorPasswordEmailOtpSuccessCount",
                experimentResultService
                        .getSuccessCountByAuthMethod(
                                "two-factor-password-email-otp"));

        model.addAttribute(
                "twoFactorPasswordEmailOtpSuccessRate",
                experimentResultService
                        .getSuccessRateByAuthMethod(
                                "two-factor-password-email-otp"));

        model.addAttribute(
                "twoFactorPasswordEmailOtpAverageAttemptCount",
                experimentResultService
                        .getAverageAttemptCountByAuthMethod(
                                "two-factor-password-email-otp"));

        model.addAttribute(
                "twoFactorPasswordEmailOtpSuccessAttackTimeTotal",
                experimentResultService
                        .getSuccessAttackTimeTotalByAuthMethod(
                                "two-factor-password-email-otp"));

        model.addAttribute(
                "twoFactorPasswordEmailOtpAverageSuccessAttackTime",
                experimentResultService
                        .getAverageSuccessAttackTimeByAuthMethod(
                                "two-factor-password-email-otp"));

        return "results";
    }

    /**
     * 選択した実験結果を削除
     */
    @PostMapping("/results/delete")
    public String deleteResults(
            @RequestParam(
                    name = "ids",
                    required = false)
            List<Long> ids) {

        experimentResultService
                .deleteResultsByIds(ids);

        return "redirect:/results";
    }

    /**
     * 全実験結果を削除
     */
    @PostMapping("/results/clear")
    public String clearResults() {

        experimentResultService.clearResults();

        return "redirect:/results";
    }

    /**
     * 多段階認証の突破情報を作成
     */
    private String createPasswordCredential(
            AttackResult result) {

        StringBuilder credential =
                new StringBuilder();

        if (result.getPassword() != null) {

            credential.append(
                    "Password="
                    + result.getPassword());
        }

        if (result.getPassword2() != null) {

            credential.append(
                    " / Password2="
                    + result.getPassword2());
        }

        if (result.getPassword3() != null) {

            credential.append(
                    " / Password3="
                    + result.getPassword3());
        }

        return credential.toString();
    }

    /**
     * 一要素・二要素認証の突破情報を作成
     */
    private String createFactorCredential(
            FactorAttackResult result) {

        StringBuilder credential =
                new StringBuilder();

        if (result.getPassword() != null) {

            credential.append(
                    "Password="
                    + result.getPassword());
        }

        if (result.getOtp() != null) {

            if (credential.length() > 0) {

                credential.append(" / ");
            }

            credential.append(
                    "Email OTP="
                    + result.getOtp());
        }

        return credential.toString();
    }
}