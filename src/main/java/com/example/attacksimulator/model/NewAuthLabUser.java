package com.example.attacksimulator.model;

public class NewAuthLabUser {

    private final String username;

    private final String password;

    private final String password2;

    private final String password3;

    public NewAuthLabUser(
            String username,
            String password,
            String password2,
            String password3) {

        this.username = username;
        this.password = password;
        this.password2 = password2;
        this.password3 = password3;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getPassword2() {
        return password2;
    }

    public String getPassword3() {
        return password3;
    }
}