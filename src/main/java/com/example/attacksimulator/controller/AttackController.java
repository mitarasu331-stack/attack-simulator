package com.example.attacksimulator.controller;

import java.time.LocalDateTime;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
import com.example.attacksimulator.model.ExperimentResult;
import com.example.attacksimulator.service.AttackService;
import com.example.attacksimulator.service.ExperimentResultService;

@Controller
public class AttackController {

    private final AttackService attackService;

    private final ExperimentResultService experimentResultService;

    public AttackController(
            AttackService attackService,
            ExperimentResultService experimentResultService) {

        this.attackService = attackService;
        this.experimentResultService =
                experimentResultService;
    }

    @GetMapping("/")
    public String index() {
        return "attack";
    }

    @PostMapping("/attack/password")
    public String passwordBruteForce(
            @RequestParam(defaultValue = "one-stage")
            String authMethod,
            Model model) {

        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        long startTime = System.nanoTime();

        AttackResult result;

        switch (authMethod) {

            case "one-stage":
                result = attackService.executeOneStage();
                break;

            case "two-stage":
                result = attackService.executeTwoStage();
                break;

            case "three-stage":
                result = attackService.executeThreeStage();
                break;

            default:
                throw new IllegalArgumentException(
                        "不正な認証方式です: "
                        + authMethod);
        }

        long endTime = System.nanoTime();

        long attackTimeMs =
                (endTime - startTime)
                / 1_000_000;

        int operationCount;

        switch (authMethod) {

            case "one-stage":
                operationCount = 3;
                break;

            case "two-stage":
                operationCount = 5;
                break;

            case "three-stage":
                operationCount = 7;
                break;

            default:
                operationCount = 0;
        }

        /*
         * 認証方式ごとの最大攻撃試行回数
         */
        int maxAttemptCount;

        switch (authMethod) {

            case "one-stage":
                maxAttemptCount = 10000;
                break;

            case "two-stage":
                maxAttemptCount = 20000;
                break;

            case "three-stage":
                maxAttemptCount = 30000;
                break;

            default:
                maxAttemptCount = 0;
        }

        /*
         * 認証方式ごとの認証構成
         */
        String authenticationConfiguration;

        switch (authMethod) {

            case "one-stage":
                authenticationConfiguration =
                        "ID + Password";
                break;

            case "two-stage":
                authenticationConfiguration =
                        "ID + Password → Password2";
                break;

            case "three-stage":
                authenticationConfiguration =
                        "ID + Password → Password2 → Password3";
                break;

            default:
                authenticationConfiguration =
                        "不明";
        }

        /*
         * 実験番号
         *
         * 現在の実験結果数 + 1
         */
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

        model.addAttribute(
                "experimentNumber",
                experimentNumber);

        model.addAttribute(
                "authMethod",
                result.getAuthMethod());

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

        return "result";
    }

    @PostMapping("/attack/email-otp")
    public String emailOtpBruteForce(
            @RequestParam(defaultValue = "10000")
            int maxAttempts,
            Model model) {

        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        long startTime = System.nanoTime();

        EmailOtpBruteForceAttack.AttackResult result =
                attackService.executeEmailOtpBruteForce(
                        maxAttempts);

        long endTime = System.nanoTime();

        long attackTimeMs =
                (endTime - startTime)
                / 1_000_000;

        /*
         * メールOTPの認証構成
         */
        String authenticationConfiguration =
                "ID + Password → Email OTP";

        /*
         * 実験番号
         */
        int experimentNumber =
                experimentResultService
                        .getResultCount() + 1;

        ExperimentResult experimentResult =
                new ExperimentResult(
                        experimentNumber,
                        "email-otp",
                        0,
                        authenticationConfiguration,
                        maxAttempts,
                        result.getAttemptCount(),
                        result.isSuccess(),
                        result.getOtp(),
                        attackTimeMs,
                        experimentDateTime);

        experimentResultService.addResult(
                experimentResult);

        model.addAttribute(
                "experimentNumber",
                experimentNumber);

        model.addAttribute(
                "authMethod",
                "email-otp");

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
                maxAttempts);

        model.addAttribute(
                "authenticationConfiguration",
                authenticationConfiguration);

        return "result";
    }

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
         * メールOTP
         */
        model.addAttribute(
                "emailOtpExperimentCount",
                experimentResultService
                        .getExperimentCountByAuthMethod(
                                "email-otp"));

        model.addAttribute(
                "emailOtpSuccessCount",
                experimentResultService
                        .getSuccessCountByAuthMethod(
                                "email-otp"));

        model.addAttribute(
                "emailOtpSuccessRate",
                experimentResultService
                        .getSuccessRateByAuthMethod(
                                "email-otp"));

        model.addAttribute(
                "emailOtpAverageAttemptCount",
                experimentResultService
                        .getAverageAttemptCountByAuthMethod(
                                "email-otp"));

        model.addAttribute(
                "emailOtpSuccessAttackTimeTotal",
                experimentResultService
                        .getSuccessAttackTimeTotalByAuthMethod(
                                "email-otp"));

        model.addAttribute(
                "emailOtpAverageSuccessAttackTime",
                experimentResultService
                        .getAverageSuccessAttackTimeByAuthMethod(
                                "email-otp"));

        return "results";
    }

    @PostMapping("/results/clear")
    public String clearResults() {

        experimentResultService.clearResults();

        return "redirect:/results";
    }

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
}