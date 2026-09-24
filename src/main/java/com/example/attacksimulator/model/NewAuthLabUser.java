package com.example.attacksimulator.model;

public class NewAuthLabUser {

	private String username;

	private String password;

	private String password2;

	private String password3;

	private String email;

	// =========================================================
	// コンストラクタ
	// =========================================================

	public NewAuthLabUser(
			String username,
			String password,
			String password2,
			String password3,
			String email) {

		this.username = username;
		this.password = password;
		this.password2 = password2;
		this.password3 = password3;
		this.email = email;
	}

	// =========================================================
	// username
	// =========================================================

	public String getUsername() {
		return username;
	}

	public void setUsername(
			String username) {

		this.username = username;
	}

	// =========================================================
	// password
	// =========================================================

	public String getPassword() {
		return password;
	}

	public void setPassword(
			String password) {

		this.password = password;
	}

	// =========================================================
	// password2
	// =========================================================

	public String getPassword2() {
		return password2;
	}

	public void setPassword2(
			String password2) {

		this.password2 = password2;
	}

	// =========================================================
	// password3
	// =========================================================

	public String getPassword3() {
		return password3;
	}

	public void setPassword3(
			String password3) {

		this.password3 = password3;
	}

	// =========================================================
	// email
	// =========================================================

	public String getEmail() {
		return email;
	}

	public void setEmail(
			String email) {

		this.email = email;
	}
}