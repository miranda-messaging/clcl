/*
 * Copyright 2017 Long Term Software LLC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ltsllc.clcl;

import com.ltsllc.common.util.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import sun.security.pkcs10.PKCS10;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by Clark on 4/3/2017.
 */
public class PrivateKey extends Key {
    public static final String ALGORITHM = "RSA";

    private java.security.PrivateKey securityPrivateKey;

    public java.security.PrivateKey getSecurityPrivateKey() {
        return securityPrivateKey;
    }

    public PrivateKey(java.security.PrivateKey privateKey) {
        securityPrivateKey = privateKey;
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getSecurityPrivateKey());
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
            cipherOutputStream.write(plainText);
            cipherOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (GeneralSecurityException|IOException e) {
            throw new EncryptionException("Exception trying to encrypt", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getSecurityPrivateKey());
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
            cipherOutputStream.write(cipherText);
            cipherOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (GeneralSecurityException|IOException e) {
            throw new EncryptionException("Exception trying to decrypt", e);
        }
    }

    public byte[] decrypt(EncryptedMessage encryptedMessage) throws EncryptionException {
        return decrypt(encryptedMessage);
    }

    @Override
    public String toPem() throws EncryptionException {
        try {
            StringWriter stringWriter = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(stringWriter);
            pemWriter.writeObject(getSecurityPrivateKey());
            pemWriter.close();

            return stringWriter.toString();
        } catch (IOException e) {
            throw new EncryptionException("Exception trying to convert private key to PEM", e);
        }
    }

    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    public java.security.cert.Certificate sign (CertificateSigningRequest certificateSigningRequest, Date notValidBefore,
                                 Date notValidAfter) throws EncryptionException
    {
        try {
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_ALGORITHM);
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.
                    createKey(getSecurityPrivateKey().getEncoded());
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(certificateSigningRequest.getPublicKey().
                    getSecurityPublicKey().getEncoded());

            X500Name issuer = new X500Name(getDn().toString());
            X500Name subject = new X500Name(certificateSigningRequest.getPublicKey().getDn().toString());
            BigInteger serialNumber = new SerialNumber().toBigInteger();
            X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(issuer, serialNumber,
                    notValidBefore, notValidAfter, subject, keyInfo);

            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);

            X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
            Certificate certificate = holder.toASN1Structure();

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());

            InputStream inputStream = new ByteArrayInputStream(certificate.getEncoded());
            return certificateFactory.generateCertificate(inputStream);
        } catch (IOException|OperatorException|CertificateException e) {
            throw new EncryptionException("Exception trying to sign CSR", e);
        }
    }
}
