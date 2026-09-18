package com.example.attacksimulator.controller;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.attacksimulator.attack.FactorAuthenticationAttack;
import com.example.attacksimulator.attack.MultiStagePasswordBruteForceAttack;
import com.example.attacksimulator.attack.PasswordBruteForceAttack;
import com.example.attacksimulator.service.AttackService;
import com.example.attacksimulator.service.ExperimentResultService;
import com.example.attacksimulator.service.NewAuthLabUserService;

@Controller
public class AttackController {

    private final AttackService attackService;

    private final ExperimentResultService
            experimentResultService;

    private final NewAuthLabUserService
            newAuthLabUserService;

    public AttackController(
            AttackService attackService,
            ExperimentResultService experimentResultService,
            NewAuthLabUserService newAuthLabUserService) {

        this.attackService = attackService;

        this.experimentResultService =
                experimentResultService;

        this.newAuthLabUserService =
                newAuthLabUserService;
    }

    // =========================================================
    // 攻撃実験画面
    // =========================================================

    @GetMapping("/")
    public String index(Model model) {

        List<String> usernames =
                newAuthLabUserService
                        .getAllUsernames();

        model.addAttribute(
                "usernames",
                usernames);

        return "attack";
    }

    // =========================================================
    // パスワード攻撃
    // =========================================================

    @PostMapping("/attack/password")
    public String attackPassword(
            @RequestParam("username")
            String username,

            @RequestParam("authMethod")
            String authMethod,

            @RequestParam(
                    value = "maxAttempts",
                    required = false,
                    defaultValue = "10000")
            int maxAttempts,

            RedirectAttributes redirectAttributes) {

        long startTime =
                System.nanoTime();

        try {

            PasswordBruteForceAttack.AttackResult
                    result =
                    attackService
                            .executePasswordBruteForce(
                                    username);

            long attackTimeMs =
                    (System.nanoTime()
                            - startTime)
                    / 1_000_000;

            int experimentNumber =
                    experimentResultService
                            .getNextExperimentNumber();

            experimentResultService.addResult(
                    experimentNumber,
                    authMethod,
                    3,
                    "ID + Password",
                    maxAttempts,
                    result.getAttemptCount(),
                    result.isSuccess(),
                    result.getPassword(),
                    attackTimeMs);

            // =================================================
            // result.html に渡す値
            // =================================================

            redirectAttributes.addFlashAttribute(
                    "authMethod",
                    authMethod);

            redirectAttributes.addFlashAttribute(
                    "stageCount",
                    1);

            redirectAttributes.addFlashAttribute(
                    "attemptCount",
                    result.getAttemptCount());

            redirectAttributes.addFlashAttribute(
                    "success",
                    result.isSuccess());

            redirectAttributes.addFlashAttribute(
                    "password",
                    result.getPassword());

            redirectAttributes.addFlashAttribute(
                    "password2",
                    null);

            redirectAttributes.addFlashAttribute(
                    "password3",
                    null);

            redirectAttributes.addFlashAttribute(
                    "otp",
                    null);

            redirectAttributes.addFlashAttribute(
                    "message",
                    result.isSuccess()
                            ? "認証突破に成功しました。"
                            : "認証突破に失敗しました。");

        } catch (Exception e) {

            redirectAttributes.addFlashAttribute(
                    "error",
                    e.getMessage());
        }

        return "redirect:/result";
    }

    // =========================================================
    // 多段階認証
    // =========================================================

    @PostMapping("/attack/multi-stage")
    public String attackMultiStage(
            @RequestParam("username")
            String username,

            @RequestParam("authMethod")
            String authMethod,

            RedirectAttributes redirectAttributes) {

        long startTime =
                System.nanoTime();

        try {

            MultiStagePasswordBruteForceAttack
                    .AttackResult result;

            int operationCount;

            int maxAttemptCount;

            // =================================================
            // 一段階認証
            // =================================================

            if ("one-stage".equals(authMethod)) {

                result =
                        attackService
                                .executeOneStage(
                                        username);

                operationCount = 3;

                maxAttemptCount = 10000;

            // =================================================
            // 二段階認証
            // =================================================

            } else if ("two-stage".equals(authMethod)) {

                result =
                        attackService
                                .executeTwoStage(
                                        username);

                operationCount = 5;

                maxAttemptCount = 20000;

            // =================================================
            // 三段階認証
            // =================================================

            } else if ("three-stage".equals(authMethod)) {

                result =
                        attackService
                                .executeThreeStage(
                                        username);

                operationCount = 7;

                maxAttemptCount = 30000;

            } else {

                throw new IllegalArgumentException(
                        "不正な認証方式です。");
            }

            long attackTimeMs =
                    (System.nanoTime()
                            - startTime)
                    / 1_000_000;

            String credential =
                    createMultiStageCredential(
                            result);

            String configuration =
                    createMultiStageConfiguration(
                            result);

            int experimentNumber =
                    experimentResultService
                            .getNextExperimentNumber();

            experimentResultService.addResult(
                    experimentNumber,
                    authMethod,
                    operationCount,
                    configuration,
                    maxAttemptCount,
                    result.getTotalAttempts(),
                    result.isSuccess(),
                    credential,
                    attackTimeMs);

            // =================================================
            // result.html に渡す値
            // =================================================

            redirectAttributes.addFlashAttribute(
                    "authMethod",
                    authMethod);

            redirectAttributes.addFlashAttribute(
                    "stageCount",
                    result.getStageCount());

            redirectAttributes.addFlashAttribute(
                    "attemptCount",
                    result.getTotalAttempts());

            redirectAttributes.addFlashAttribute(
                    "success",
                    result.isSuccess());

            redirectAttributes.addFlashAttribute(
                    "password",
                    result.getPassword());

            redirectAttributes.addFlashAttribute(
                    "password2",
                    result.getPassword2());

            redirectAttributes.addFlashAttribute(
                    "password3",
                    result.getPassword3());

            redirectAttributes.addFlashAttribute(
                    "otp",
                    null);

            redirectAttributes.addFlashAttribute(
                    "message",
                    result.isSuccess()
                            ? "認証突破に成功しました。"
                            : "認証突破に失敗しました。");

        } catch (Exception e) {

            redirectAttributes.addFlashAttribute(
                    "error",
                    e.getMessage());
        }

        return "redirect:/result";
    }

    // =========================================================
    // 要素認証
    // =========================================================

    @PostMapping("/attack/factor")
    public String attackFactor(
            @RequestParam("username")
            String username,

            @RequestParam("authMethod")
            String authMethod,

            @RequestParam(
                    value = "maxAttempts",
                    required = false,
                    defaultValue = "10000")
            int maxAttempts,

            RedirectAttributes redirectAttributes) {

        long startTime =
                System.nanoTime();

        try {

            FactorAuthenticationAttack
                    .FactorAttackResult result;

            int operationCount;

            int maxAttemptCount;

            // =================================================
            // 一要素認証：Password
            // =================================================

            if ("one-factor-password"
                    .equals(authMethod)) {

                result =
                        attackService
                                .executeOneFactorPassword(
                                        username);

                operationCount = 3;

                maxAttemptCount = 10000;

            // =================================================
            // 一要素認証：Email OTP
            // =================================================

            } else if ("one-factor-email-otp"
                    .equals(authMethod)) {

                result =
                        attackService
                                .executeOneFactorEmailOtp(
                                        maxAttempts);

                operationCount = 3;

                maxAttemptCount = maxAttempts;

            // =================================================
            // 二要素認証
            // Password → Email OTP
            // =================================================

            } else if ("two-factor-password-email-otp"
                    .equals(authMethod)) {

                result =
                        attackService
                                .executeTwoFactorPasswordEmailOtp(
                                        username,
                                        maxAttempts);

                operationCount = 5;

                maxAttemptCount =
                        10000 + maxAttempts;

            } else {

                throw new IllegalArgumentException(
                        "不正な認証方式です。");
            }

            long attackTimeMs =
                    (System.nanoTime()
                            - startTime)
                    / 1_000_000;

            String credential =
                    createFactorCredential(
                            result);

            int experimentNumber =
                    experimentResultService
                            .getNextExperimentNumber();

            experimentResultService.addResult(
                    experimentNumber,
                    result.getAuthMethod(),
                    operationCount,
                    result.getAuthenticationConfiguration(),
                    maxAttemptCount,
                    result.getAttemptCount(),
                    result.isSuccess(),
                    credential,
                    attackTimeMs);

            // =================================================
            // result.html に渡す値
            // =================================================

            redirectAttributes.addFlashAttribute(
                    "authMethod",
                    authMethod);

            redirectAttributes.addFlashAttribute(
                    "attemptCount",
                    result.getAttemptCount());

            redirectAttributes.addFlashAttribute(
                    "success",
                    result.isSuccess());

            redirectAttributes.addFlashAttribute(
                    "password",
                    result.getPassword());

            redirectAttributes.addFlashAttribute(
                    "otp",
                    result.getOtp());

            redirectAttributes.addFlashAttribute(
                    "password2",
                    null);

            redirectAttributes.addFlashAttribute(
                    "password3",
                    null);

            // =================================================
            // Passwordの場合だけstageCountを1にする
            // =================================================

            if ("one-factor-password"
                    .equals(authMethod)) {

                redirectAttributes.addFlashAttribute(
                        "stageCount",
                        1);

            } else if ("one-factor-email-otp"
                    .equals(authMethod)) {

                redirectAttributes.addFlashAttribute(
                        "stageCount",
                        1);

            } else {

                redirectAttributes.addFlashAttribute(
                        "stageCount",
                        2);
            }

            redirectAttributes.addFlashAttribute(
                    "message",
                    result.isSuccess()
                            ? "認証突破に成功しました。"
                            : "認証突破に失敗しました。");

        } catch (Exception e) {

            redirectAttributes.addFlashAttribute(
                    "error",
                    e.getMessage());
        }

        return "redirect:/result";
    }

    // =========================================================
    // 1回の攻撃結果画面
    // =========================================================

    @GetMapping("/result")
    public String result() {

        return "result";
    }

 // =========================================================
 // 実験結果一覧画面
 // =========================================================

 @GetMapping("/results")
 public String results(Model model) {

     // =====================================================
     // 全実験結果
     // =====================================================

     model.addAttribute(
             "results",
             experimentResultService
                     .getAllResults());


     // =====================================================
     // 一段階認証
     // =====================================================

     addSummaryToModel(
             model,
             "one-stage",
             "oneStage");


     // =====================================================
     // 二段階認証
     // =====================================================

     addSummaryToModel(
             model,
             "two-stage",
             "twoStage");


     // =====================================================
     // 三段階認証
     // =====================================================

     addSummaryToModel(
             model,
             "three-stage",
             "threeStage");


     // =====================================================
     // 一要素認証（Password）
     // =====================================================

     addSummaryToModel(
             model,
             "one-factor-password",
             "oneFactorPassword");


     // =====================================================
     // 一要素認証（Email OTP）
     // =====================================================

     addSummaryToModel(
             model,
             "one-factor-email-otp",
             "oneFactorEmailOtp");


     // =====================================================
     // 二要素認証（Password + Email OTP）
     // =====================================================

     addSummaryToModel(
             model,
             "two-factor-password-email-otp",
             "twoFactorPasswordEmailOtp");


     return "results";
 }


 // =========================================================
 // 認証方式ごとの集計値をModelに設定
 // =========================================================

 private void addSummaryToModel(
	        Model model,
	        String authMethod,
	        String prefix) {

	    // 総実験回数
	    int experimentCount =
	            experimentResultService
	                    .getExperimentCountByAuthMethod(
	                            authMethod);

	    model.addAttribute(
	            prefix + "ExperimentCount",
	            experimentCount);

	    // 成功回数
	    int successCount =
	            experimentResultService
	                    .getSuccessCountByAuthMethod(
	                            authMethod);

	    model.addAttribute(
	            prefix + "SuccessCount",
	            successCount);

	    // 認証突破率
	    double successRate =
	            experimentResultService
	                    .getSuccessRateByAuthMethod(
	                            authMethod);

	    model.addAttribute(
	            prefix + "SuccessRate",
	            successRate);

	    // 平均攻撃試行回数
	    double averageAttemptCount =
	            experimentResultService
	                    .getAverageAttemptCountByAuthMethod(
	                            authMethod);

	    model.addAttribute(
	            prefix + "AverageAttemptCount",
	            averageAttemptCount);

	    // 成功時の攻撃時間合計
	    long successAttackTimeTotal =
	            experimentResultService
	                    .getSuccessAttackTimeTotalByAuthMethod(
	                            authMethod);

	    model.addAttribute(
	            prefix + "SuccessAttackTimeTotal",
	            successAttackTimeTotal);

	    // 平均攻撃成功時間
	    double averageSuccessAttackTime =
	            experimentResultService
	                    .getAverageSuccessAttackTimeByAuthMethod(
	                            authMethod);

	    model.addAttribute(
	            prefix + "AverageSuccessAttackTime",
	            averageSuccessAttackTime);
	}

    // =========================================================
    // 選択した結果を削除
    // =========================================================

    @PostMapping("/results/delete")
    public String deleteResults(
            @RequestParam(
                    value = "ids",
                    required = false)
            List<Long> ids) {

        if (ids != null && !ids.isEmpty()) {

            experimentResultService
                    .deleteResults(ids);
        }

        return "redirect:/results";
    }

    // =========================================================
    // 全結果削除
    // =========================================================

    @PostMapping("/results/clear")
    public String clearResults() {

        experimentResultService
                .clearResults();

        return "redirect:/results";
    }

    // =========================================================
    // 多段階認証の認証情報表示用
    // =========================================================

    private String createMultiStageCredential(
            MultiStagePasswordBruteForceAttack
                    .AttackResult result) {

        if (result.getStageCount() == 1) {

            return result.getPassword();

        } else if (result.getStageCount() == 2) {

            return result.getPassword()
                    + " → "
                    + result.getPassword2();

        } else if (result.getStageCount() == 3) {

            return result.getPassword()
                    + " → "
                    + result.getPassword2()
                    + " → "
                    + result.getPassword3();
        }

        return null;
    }

    // =========================================================
    // 多段階認証の構成表示用
    // =========================================================

    private String createMultiStageConfiguration(
            MultiStagePasswordBruteForceAttack
                    .AttackResult result) {

        if (result.getStageCount() == 1) {

            return "ID + Password";

        } else if (result.getStageCount() == 2) {

            return "ID + Password → Password2";

        } else if (result.getStageCount() == 3) {

            return "ID + Password → Password2 → Password3";
        }

        return null;
    }

    // =========================================================
    // 要素認証の認証情報表示用
    // =========================================================

    private String createFactorCredential(
            FactorAuthenticationAttack
                    .FactorAttackResult result) {

        String password =
                result.getPassword();

        String otp =
                result.getOtp();

        if (password != null
                && otp != null) {

            return password
                    + " → "
                    + otp;
        }

        if (password != null) {

            return password;
        }

        if (otp != null) {

            return otp;
        }

        return null;
    }
}