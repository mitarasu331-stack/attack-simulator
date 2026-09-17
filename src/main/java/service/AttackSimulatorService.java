package service;

import java.util.Scanner;

import org.springframework.stereotype.Service;

@Service
public class AttackSimulatorService {

    public void start() {

        Scanner scanner = new Scanner(System.in);

        System.out.println("=== 認証攻撃シミュレーター ===");
        System.out.println();
        System.out.println("認証方式を選択してください。");
        System.out.println();
        System.out.println("1. 一段階認証（知識）");
        System.out.println("2. 二段階認証（知識＋知識）");
        System.out.println("3. 三段階認証（知識＋知識＋知識）");
        System.out.println("4. 一要素認証（知識）");
        System.out.println("5. 一要素認証（所有）");
        System.out.println("6. 二要素認証（知識＋所有）");
        System.out.println();
        System.out.print("番号を入力してください：");

        int choice = scanner.nextInt();

        switch (choice) {
            case 1:
                System.out.println("一段階認証（知識）を選択しました。");
                break;

            case 2:
                System.out.println("二段階認証（知識＋知識）を選択しました。");
                break;

            case 3:
                System.out.println("三段階認証（知識＋知識＋知識）を選択しました。");
                break;

            case 4:
                System.out.println("一要素認証（知識）を選択しました。");
                break;

            case 5:
                System.out.println("一要素認証（所有）を選択しました。");
                break;

            case 6:
                System.out.println("二要素認証（知識＋所有）を選択しました。");
                break;

            default:
                System.out.println("正しい番号を入力してください。");
        }
    }
}