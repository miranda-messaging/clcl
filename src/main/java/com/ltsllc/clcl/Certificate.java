package com.ltsllc.clcl;

public class Certificate {
    private java.security.cert.Certificate certificate;

    public java.security.cert.Certificate getCertificate() {
        return certificate;
    }

    public Certificate (java.security.cert.Certificate certificate) {
        this.certificate = certificate;
    }

    public java.security.cert.Certificate toJscCertificate () {
        return getCertificate();
    }
}
