/*
 * Copyright  2017 Long Term Software LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.ltsllc.clcl;

import com.sun.deploy.uitoolkit.impl.fx.ui.CertificateDialog;
import jdk.internal.util.xml.impl.Input;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;
import org.bouncycastle.jcajce.provider.keystore.bc.BcKeyStoreSpi;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAAsymmetricKeyUnwrapper;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
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

    public String toPem () throws IOException {
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        pemWriter.writeObject(getCertificate());
        pemWriter.close();
        return stringWriter.toString();
    }

    public static Certificate fromPEM (String pem) throws IOException, GeneralSecurityException {
        StringReader stringReader = new StringReader(pem);
        PEMParser pemParser = new PEMParser(stringReader);
        X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) pemParser.readObject();
        org.bouncycastle.asn1.x509.Certificate certificate = x509CertificateHolder.toASN1Structure();

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certificate.getEncoded());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
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

    /*
     * Store the certificate
     */
    public void store(String filename) throws EncryptionException {
        JavaKeyStore javaKeyStore = new JavaKeyStore();

        javaKeyStore.add(null,this);
        javaKeyStore.store();
    }

}
