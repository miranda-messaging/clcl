package com.ltsllc.clcl;

import org.bouncycastle.openssl.PEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;

public class KeyPair {
    public static final String ALGORITHM = "RSA";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public static KeyPair newKeys () throws EncryptionException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = new PublicKey(keyPair.getPublic());
            PrivateKey privateKey = new PrivateKey(keyPair.getPrivate());
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Exception trying to generate new keys", e);
        }
    }

    public String toPem () throws EncryptionException {
        try {
            StringWriter stringWriter = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(stringWriter);
            java.security.KeyPair jsKeyPair = new java.security.KeyPair(getPublicKey().getSecurityPublicKey(),
                    getPrivateKey().getSecurityPrivateKey());

            pemWriter.writeObject(jsKeyPair);
            pemWriter.close();

            return stringWriter.toString();
        } catch (IOException e) {
            throw new EncryptionException("Exception trying to convert key pair to PEM", e);
        }
    }

    public CertificateSigningRequest createCertificateSigningRequest () throws EncryptionException {
        return getPublicKey().createCertificateSigningRequest(getPrivateKey());
    }
}
