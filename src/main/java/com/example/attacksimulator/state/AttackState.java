package com.example.attacksimulator.state;

import org.springframework.stereotype.Component;
//全部なぎ
@Component
public class AttackState {

    private boolean otpTimedOut = false;

    public boolean isOtpTimedOut() {//タイムアウトしたかどうか受け取る
        return otpTimedOut;
    }

    public void setOtpTimedOut(boolean otpTimedOut) {//タイムアウトをfalseに設定する
        this.otpTimedOut = otpTimedOut;
    }
}