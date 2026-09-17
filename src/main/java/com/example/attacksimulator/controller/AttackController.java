package com.example.attacksimulator.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.attacksimulator.attack.EmailOtpBruteForceAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack.AttackResult;
import com.example.attacksimulator.service.AttackService;

@Controller
public class AttackController {

    private final AttackService attackService;

    public AttackController(AttackService attackService) {
        this.attackService = attackService;
    }

    /**
     * Attack Simulatorのトップ画面
     */
    @GetMapping("/")
    public String index() {
        return "attack";
    }

    /**
     * パスワード総当たり攻撃
     *
     * 一段階・二段階・三段階を選択して実行する。
     */
    @PostMapping("/attack/password")
    public String passwordBruteForce(
            @RequestParam(defaultValue = "one-stage")
            String authMethod,
            Model model) {

        AttackResult result;

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

        // 認証方式
        model.addAttribute(
                "authMethod",
                result.getAuthMethod());

        // 成功・失敗
        model.addAttribute(
                "success",
                result.isSuccess());

        // 認証段階数
        model.addAttribute(
                "stageCount",
                result.getStageCount());

        // 総試行回数
        model.addAttribute(
                "attemptCount",
                result.getTotalAttempts());

        // Password
        model.addAttribute(
                "password",
                result.getPassword());

        // Password2
        model.addAttribute(
                "password2",
                result.getPassword2());

        // Password3
        model.addAttribute(
                "password3",
                result.getPassword3());

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

        EmailOtpBruteForceAttack.AttackResult result =
                attackService.executeEmailOtpBruteForce(
                        maxAttempts);

        // 認証方式
        model.addAttribute(
                "authMethod",
                "email-otp");

        // 成功・失敗
        model.addAttribute(
                "success",
                result.isSuccess());

        // 認証段階数はメールOTPでは使用しない
        model.addAttribute(
                "stageCount",
                null);

        // 実際の試行回数
        model.addAttribute(
                "attemptCount",
                result.getAttemptCount());

        // 突破したOTP
        model.addAttribute(
                "otp",
                result.getOtp());

        return "result";
    }
}
