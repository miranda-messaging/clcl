package com.ltsllc.clcl;

public class EncryptionException extends Exception {
    public EncryptionException (String message) {
        super(message);
    }

    public EncryptionException (String message, Throwable cause) {
        super(message, cause);
    }
}
