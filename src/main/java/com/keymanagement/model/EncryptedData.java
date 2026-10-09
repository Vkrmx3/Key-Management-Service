package com.keymanagement.model;

public class EncryptedData {
    private final byte[] ciphertext;
    private final byte[] nonce;
    private final String keyId;

    public EncryptedData(byte[] ciphertext, byte[] nonce) {
        this(ciphertext, nonce, null);
    }

    public EncryptedData(byte[] ciphertext, byte[] nonce, String keyId) {
        this.ciphertext = ciphertext;
        this.nonce = nonce;
        this.keyId = keyId;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public String getKeyId() {
        return keyId;
    }
}
