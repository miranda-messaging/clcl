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

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;

/**
 * A class that can be used to encrypt or decrypt messages.
 *
 * <p>
 *     This class provides utility methods for its subclasses like the {@link #encrypt(String, byte[])}
 *     and {@link #decrypt(EncryptedMessage)} methods.
 * </p>
 */
abstract public class Key implements Serializable {
    abstract public byte[] encrypt (byte[] plainText) throws EncryptionException;
    abstract public byte[] decrypt (byte[] cipherText) throws EncryptionException;
    abstract public String toPem () throws EncryptionException;

    public static String SESSION_ALGORITHM = "AES";

    private DistinguishedName dn;

    public DistinguishedName getDn() {
        return dn;
    }

    public void setDn(DistinguishedName dn) {
        this.dn = dn;
    }

    /**
     * Encrpyt a message.
     *
     * <p>
     *     This is a utility method for encrypting messages.
     *     It encrypts messages with a "fast" algorithm and the session key used is encrypted
     *     with the object to provide security.
     * </p>
     *
     * @param algorithm The algorithm that should be used to encrypt the message.
     * @param plainText The message to be encrypted.
     * @return An object containing the encrypted message and the encrypted session key.
     */
    public EncryptedMessage encrypt (String algorithm, byte[] plainText)
            throws EncryptionException
    {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            SecretKey sessionKey = keyGenerator.generateKey();

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
            cipherOutputStream.write(plainText);
            cipherOutputStream.close();

            byte[] sessionKeyCipherText = encrypt(sessionKey.getEncoded());
            String sessionKeyCipherTextString = Utils.bytesToString(sessionKeyCipherText);
            String cipherTextString = Utils.bytesToString(byteArrayOutputStream.toByteArray());

            EncryptedMessage encryptedMessage = new EncryptedMessage(algorithm, sessionKeyCipherTextString, cipherTextString);

            return encryptedMessage;
        } catch (GeneralSecurityException|IOException e) {
            throw new EncryptionException("Exception trying to encrypt message", e);
        }
    }

    /**
     * Decrypt a message.
     *
     * <p>
     *     This is a utility method for decrypting messages.
     *     A message is encrypted with a "fast" algorithm whose key is part of the message object.
     * </p>
     *
     * @param encryptedMessage The message to be decrypted.
     * @return The decrypted message.
     * @throws EncryptionException If there is a problem decrypting the message.
     */
    public byte[] decrypt (EncryptedMessage encryptedMessage)
        throws EncryptionException
    {
        try {
            byte[] sessionKeyPlainText = decrypt(Utils.hexStringToBytes(encryptedMessage.getKey()));
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(encryptedMessage.getAlgorithm());

            SecretKeySpec secretKeySpec = new SecretKeySpec(sessionKeyPlainText, encryptedMessage.getAlgorithm());
            SecretKey sessionKey = secretKeyFactory.generateSecret(secretKeySpec);

            Cipher cipher = Cipher.getInstance(encryptedMessage.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, sessionKey);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
            cipherOutputStream.write(Utils.hexStringToBytes(encryptedMessage.getMessage()));
            cipherOutputStream.close();

            return byteArrayOutputStream.toByteArray();
        } catch (GeneralSecurityException|IOException e) {
            throw new EncryptionException("Exception trying to decrypt message", e);
        }
    }
}
