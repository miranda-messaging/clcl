package com.ltsllc.clcl;

import com.sun.deploy.uitoolkit.impl.fx.ui.CertificateDialog;
import jdk.internal.util.xml.impl.Input;
import org.bouncycastle.openssl.PEMWriter;

import java.io.*;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Certificate {
    private X509Certificate certificate;

    public X509Certificate getCertificate() {
        return certificate;
    }

    public Certificate (X509Certificate certificate) {
        this.certificate = certificate;
    }

    public java.security.cert.Certificate toJscCertificate () {
        return getCertificate();
    }

    public String toPem () throws IOException {
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        pemWriter.writeObject(getCertificate());
        pemWriter.close();
        return stringWriter.toString();
    }

    public String toPem (String passwordString) {
        return null;
    }

    public static Certificate fromPEM (String pem) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pem.getBytes());
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);

        return new Certificate(x509Certificate);
    }

    public boolean equals (Object o) {
        if (o == null || !(o instanceof Certificate))
            return false;

        Certificate other = (Certificate) o;
        DistinguishedName myDn = getSubject();
        DistinguishedName otherDn = other.getSubject();

        if (!myDn.equals(otherDn))
            return false;

        myDn = getIssuer();
        otherDn = other.getIssuer();

        return myDn.equals(otherDn);
    }

    public BigInteger getSerialnumber() {
        return  getCertificate().getSerialNumber();
    }

    public DistinguishedName getSubject () {
        return new DistinguishedName(getCertificate().getSubjectDN());
    }

    public DistinguishedName getIssuer () {
        return new DistinguishedName(getCertificate().getIssuerDN());
    }
}
