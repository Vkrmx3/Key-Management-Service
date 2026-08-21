package com.keymanagement.dto;

public class EncryptResponse {
    private String ciphertext;
    private String nonce;

    public EncryptResponse() {
    }

    public EncryptResponse(String ciphertext, String nonce) {
        this.ciphertext = ciphertext;
        this.nonce = nonce;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }
}
