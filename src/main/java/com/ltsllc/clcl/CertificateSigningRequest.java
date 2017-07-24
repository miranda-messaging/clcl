package com.ltsllc.clcl;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;

public class CertificateSigningRequest {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public CertificateSigningRequest (PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";

    public PKCS10 toPKCS10 () throws EncryptionException {
        try {
            PKCS10 pkcs10 = new PKCS10(getPublicKey().getSecurityPublicKey());

            X500Name x500Name = new X500Name(getPublicKey().getDn().toString());

            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(getPrivateKey().getSecurityPrivateKey());

            pkcs10.encodeAndSign(x500Name, signature);

            return pkcs10;
        } catch (GeneralSecurityException|IOException e) {
            throw new EncryptionException("Exception trying to create CSR", e);
        }
    }
}
