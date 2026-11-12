
package com.example.attacksimulator.state;

import org.springframework.stereotype.Component;

@Component
public class AttackState {

	// OTPタイムアウト状態
	private volatile boolean otpTimedOut = false;

	// タイムアウトしたかどうかを取得
	public boolean isOtpTimedOut() {
		return otpTimedOut;
	}

	// タイムアウト状態を設定
	public void setOtpTimedOut(boolean otpTimedOut) {
		this.otpTimedOut = otpTimedOut;
	}

}
