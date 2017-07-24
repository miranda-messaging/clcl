package com.ltsllc.clcl;

/**
 * Created by Clark on 6/2/2017.
 */
public class EncryptedMessage {
    private String algorithm;
    private String key;
    private String message;

    public EncryptedMessage() {}

    public EncryptedMessage(String algorithm, String key, String message) {
        this.algorithm = algorithm;
        this.key = key;
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}
