package com.ltsllc.clcl.test;

import com.ltsllc.clcl.*;
import com.ltsllc.common.test.TestCase;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.Calendar;
import java.util.Date;

public class EncryptionTestCase extends TestCase {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private CertificateSigningRequest csr;
    private Certificate certificate;

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public CertificateSigningRequest getCsr() {
        return csr;
    }

    public void setCsr(CertificateSigningRequest csr) {
        this.csr = csr;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public static DistinguishedName createDn () {
        DistinguishedName dn = new DistinguishedName();

        dn.setCountryCode("US");
        dn.setState("Colorado");
        dn.setCity("Denver");
        dn.setCompany("Long Term Software LLC");
        dn.setDivision("Development");
        dn.setName("foo.com");

        return dn;
    }

    public KeyPair createKeyPair (int keySize) throws GeneralSecurityException {
        DistinguishedName dn = createDn();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        java.security.KeyPair jsKeyPair = keyPairGenerator.genKeyPair();

        PublicKey publicKey = new PublicKey(jsKeyPair.getPublic());
        publicKey.setDn(dn);
        PrivateKey privateKey = new PrivateKey(jsKeyPair.getPrivate());
        privateKey.setDn(dn);

        setPublicKey(publicKey);
        setPrivateKey(privateKey);

        return new KeyPair(publicKey, privateKey);
    }

    public Certificate createCertificate () throws GeneralSecurityException, EncryptionException {
        KeyPair keyPair = createKeyPair(2048);

        CertificateSigningRequest csr = keyPair.createCertificateSigningRequest();

        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.YEAR, 1);
        Date aYearFromNow = calendar.getTime();

        Certificate certificate = keyPair.getPrivateKey().sign(csr, now, aYearFromNow);
        setCertificate(certificate);

        return certificate;
    }
}
