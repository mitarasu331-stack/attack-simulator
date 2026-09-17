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

    /**
     * 攻撃シミュレーション画面
     */
    @GetMapping("/")
    public String index() {
        return "attack";
    }

    /**
     * パスワード方式の攻撃
     */
    @PostMapping("/attack/password")
    public String passwordBruteForce(
            @RequestParam(defaultValue = "one-stage")
            String authMethod,
            Model model) {

        /*
         * 実験開始日時を記録
         */
        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        /*
         * 攻撃開始
         */
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

        /*
         * 攻撃終了
         */
        long endTime = System.nanoTime();

        /*
         * 攻撃時間をミリ秒に変換
         */
        long attackTimeMs =
                (endTime - startTime)
                / 1_000_000;

        /*
         * 認証操作回数
         *
         * 一段階認証 = 3
         * 二段階認証 = 5
         * 三段階認証 = 7
         */
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
         * 突破した認証情報
         */
        String credential =
                createPasswordCredential(result);

        /*
         * 実験結果を保存
         */
        ExperimentResult experimentResult =
                new ExperimentResult(
                        authMethod,
                        operationCount,
                        result.getTotalAttempts(),
                        result.isSuccess(),
                        credential,
                        attackTimeMs,
                        experimentDateTime);

        experimentResultService.addResult(
                experimentResult);

        /*
         * 結果画面へ渡すデータ
         */
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

        return "result";
    }

    /**
     * メールOTP方式の攻撃
     */
    @PostMapping("/attack/email-otp")
    public String emailOtpBruteForce(
            @RequestParam(defaultValue = "10000")
            int maxAttempts,
            Model model) {

        /*
         * 実験開始日時を記録
         */
        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        /*
         * 攻撃開始
         */
        long startTime = System.nanoTime();

        EmailOtpBruteForceAttack.AttackResult result =
                attackService.executeEmailOtpBruteForce(
                        maxAttempts);

        /*
         * 攻撃終了
         */
        long endTime = System.nanoTime();

        /*
         * 攻撃時間
         */
        long attackTimeMs =
                (endTime - startTime)
                / 1_000_000;

        /*
         * メールOTPの実験結果を保存
         */
        ExperimentResult experimentResult =
                new ExperimentResult(
                        "email-otp",
                        0,
                        result.getAttemptCount(),
                        result.isSuccess(),
                        result.getOtp(),
                        attackTimeMs,
                        experimentDateTime);

        experimentResultService.addResult(
                experimentResult);

        /*
         * 結果画面へ渡すデータ
         */
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

        return "result";
    }

    /**
     * 実験結果一覧
     */
    @GetMapping("/results")
    public String results(Model model) {

        /*
         * 全実験結果
         */
        model.addAttribute(
                "results",
                experimentResultService.getResults());

        /*
         * --------------------------------
         * 一段階認証
         * --------------------------------
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
         * --------------------------------
         * 二段階認証
         * --------------------------------
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
         * --------------------------------
         * 三段階認証
         * --------------------------------
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
         * --------------------------------
         * メールOTP
         * --------------------------------
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

    /**
     * 実験結果をすべて削除
     */
    @PostMapping("/results/clear")
    public String clearResults() {

        experimentResultService.clearResults();

        return "redirect:/results";
    }

    /**
     * パスワード方式の認証情報を作成
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
}