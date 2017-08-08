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

import org.bouncycastle.openssl.PEMWriter;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;

/**
 * Created by Clark on 4/2/2017.
 */
public class PublicKey extends Key {
    public static final String ALGORITHM = "RSA";
    public static final String SESSION_ALGORITHM = "AES";

    private java.security.PublicKey securityPublicKey;

    public java.security.PublicKey getSecurityPublicKey() {
        return securityPublicKey;
    }

    public PublicKey(java.security.PublicKey publicKey) {
        this.securityPublicKey = publicKey;
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getSecurityPublicKey());

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
            cipher.init(Cipher.DECRYPT_MODE, getSecurityPublicKey());

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);

            cipherOutputStream.write(cipherText);
            cipherOutputStream.close();

            return byteArrayOutputStream.toByteArray();
        } catch (GeneralSecurityException|IOException e) {
            throw new EncryptionException("Exception trying to decrypt", e);
        }
    }

    public EncryptedMessage toEncryptedMessage (byte[] plainText) throws EncryptionException {
        return encrypt(SESSION_ALGORITHM, plainText);
    }

    public String toPem () throws EncryptionException {
        try {
            StringWriter stringWriter = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(stringWriter);
            pemWriter.writeObject(getSecurityPublicKey());
            pemWriter.close();

            return stringWriter.toString();
        } catch (IOException e) {
            throw new EncryptionException("Exception trying to covert public key to PEM", e);
        }
    }

    public CertificateSigningRequest createCertificateSigningRequest (PrivateKey privateKey) throws EncryptionException  {
        return new CertificateSigningRequest (this, privateKey);
    }

    @Override
    public String toPem(String password) throws EncryptionException {
        return null;
    }


    public void fromPEM(String pem) throws EncryptionException {

    }


    public void fromPEM(String pem, String passwordString) throws EncryptionException {

    }
}
