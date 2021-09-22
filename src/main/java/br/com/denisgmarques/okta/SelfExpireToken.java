package br.com.icolabora.okta;

import lombok.Getter;

public class SelfExpireToken {
    private long expiryDate;

    @Getter
    private String value;

    public SelfExpireToken(String token, int seconds) {
        this.value = token;
        this.expiryDate = System.currentTimeMillis() + seconds * 1000;
    }
    public boolean isExpired() {
        return System.currentTimeMillis() >= expiryDate;
    }
}
