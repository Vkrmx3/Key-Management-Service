package com.keymanagement.dto;

public class EncryptResponse {
    private String ciphertext;
    private String nonce;
    private String keyId;

    public EncryptResponse() {
    }

    public EncryptResponse(String ciphertext, String nonce) {
        this(ciphertext, nonce, null);
    }

    public EncryptResponse(String ciphertext, String nonce, String keyId) {
        this.ciphertext = ciphertext;
        this.nonce = nonce;
        this.keyId = keyId;
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

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
