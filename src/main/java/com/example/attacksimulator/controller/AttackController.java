package com.example.attacksimulator.controller;

import java.time.LocalDateTime;
import java.util.List;

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

    private final ExperimentResultService
            experimentResultService;

    public AttackController(
            AttackService attackService,
            ExperimentResultService experimentResultService) {

        this.attackService = attackService;

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
     * パスワード総当たり攻撃
     *
     * 一段階・二段階・三段階
     */
    @PostMapping("/attack/password")
    public String passwordBruteForce(
            @RequestParam(defaultValue = "one-stage")
            String authMethod,
            Model model) {

        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        long startTime =
                System.nanoTime();

        AttackResult result;

        /*
         * 認証方式によって攻撃を実行
         */
        switch (authMethod) {

            case "one-stage":
                result =
                        attackService.executeOneStage();
                break;

            case "two-stage":
                result =
                        attackService.executeTwoStage();
                break;

            case "three-stage":
                result =
                        attackService.executeThreeStage();
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

        /*
         * 認証操作回数
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
         * 最大攻撃試行回数
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
         * 認証構成
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
         * 現在のDB内の実験結果数 + 1
         */
        int experimentNumber =
                experimentResultService
                        .getResultCount() + 1;

        /*
         * 攻撃によって突破した認証情報
         */
        String credential =
                createPasswordCredential(result);

        /*
         * 実験結果を作成
         */
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

        /*
         * MySQLへ保存
         */
        experimentResultService.addResult(
                experimentResult);

        /*
         * 結果画面へ渡すデータ
         */
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

    /**
     * メールOTP総当たり攻撃
     */
    @PostMapping("/attack/email-otp")
    public String emailOtpBruteForce(
            @RequestParam(defaultValue = "10000")
            int maxAttempts,
            Model model) {

        LocalDateTime experimentDateTime =
                LocalDateTime.now();

        long startTime =
                System.nanoTime();

        EmailOtpBruteForceAttack.AttackResult result =
                attackService.executeEmailOtpBruteForce(
                        maxAttempts);

        long endTime =
                System.nanoTime();

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

        /*
         * 実験結果を作成
         */
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

        /*
         * MySQLへ保存
         */
        experimentResultService.addResult(
                experimentResult);

        /*
         * 結果画面へ渡すデータ
         */
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

    /**
     * 実験結果一覧
     */
    @GetMapping("/results")
    public String results(Model model) {

        /*
         * DBから全実験結果を取得
         */
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

    /**
     * 選択した実験結果を複数削除
     *
     * DBのIDを使用して削除する
     */
    @PostMapping("/results/delete")
    public String deleteResults(
            @RequestParam(
                    name = "ids",
                    required = false)
            List<Long> ids) {

        /*
         * 選択された実験結果を削除
         */
        experimentResultService
                .deleteResultsByIds(ids);

        /*
         * 削除後は実験番号を
         * 1, 2, 3... と詰め直す
         *
         * サービス側で実行済み
         */
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
     * パスワード認証情報を文字列化
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