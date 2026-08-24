package com.keymanagement.model;

public class EncryptedData {
    private final byte[] ciphertext;
    private final byte[] nonce;

    public EncryptedData(byte[] ciphertext, byte[] nonce) {
        this.ciphertext = ciphertext;
        this.nonce = nonce;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[] getNonce() {
        return nonce;
    }
}
