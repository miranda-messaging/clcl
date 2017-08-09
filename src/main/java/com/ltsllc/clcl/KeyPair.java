package com.ltsllc.clcl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;

public class KeyPair {
    public static final String ALGORITHM = "RSA";
    public static final String SESSION_ALGORITHM = "AES";

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

    public static KeyPair fromPem (String pem) throws EncryptionException {
        try {
            StringReader stringReader = new StringReader(pem);
            PEMParser pemParser = new PEMParser(stringReader);
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
            JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
            jcaPEMKeyConverter.setProvider(new BouncyCastleProvider());
            java.security.KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
            PublicKey publicKey = new PublicKey(keyPair.getPublic());
            PrivateKey privateKey = new PrivateKey(keyPair.getPrivate());
            return new KeyPair(publicKey, privateKey);
        } catch (IOException e) {
            throw new EncryptionException("Exception trying to create PEM", e);
        }
    }

    public String toPem (String password) throws EncryptionException {
        try {
            StringWriter stringWriter = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(stringWriter);
            JcePEMEncryptorBuilder jcePEMEncryptorBuilder = new JcePEMEncryptorBuilder(SESSION_ALGORITHM);
            jcePEMEncryptorBuilder.setProvider(new BouncyCastleProvider());
            PEMEncryptor pemEncryptor = jcePEMEncryptorBuilder.build(password.toCharArray());
            java.security.KeyPair keyPair = new java.security.KeyPair(getPublicKey().getSecurityPublicKey(), getPrivateKey().getSecurityPrivateKey());
            pemWriter.writeObject(keyPair, pemEncryptor);
            pemWriter.close();
            return stringWriter.toString();
        } catch (IOException e) {
            throw new EncryptionException("Exception trying to create PEM", e);
        }
    }

    public static KeyPair fromPem (String pem, String password) throws EncryptionException {
        try {
            StringReader stringReader = new StringReader(pem);
            PEMParser pemParser = new PEMParser(stringReader);
            Object o = pemParser.readObject();
            return null;
        } catch (IOException e) {
            throw new EncryptionException("Exception reading PEM", e);
        }
    }

    public CertificateSigningRequest createCertificateSigningRequest () throws EncryptionException {
        return getPublicKey().createCertificateSigningRequest(getPrivateKey());
    }

    public boolean equals (Object o) {
        if (o == null || !(o instanceof KeyPair))
            return false;

        KeyPair other = (KeyPair) o;
        return getPublicKey().equals(other.getPublicKey()) && getPrivateKey().equals(other.getPrivateKey());
    }
}
