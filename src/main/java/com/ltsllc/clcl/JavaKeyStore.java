package com.ltsllc.clcl;

import com.ltsllc.common.util.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.*;

/**
 * A Java key store.
 *
 * <p>
 *     An instance of this class represents
 * </p>
 */
public class JavaKeyStore {
    public static class ObjectProtectionParameter extends Object implements KeyStore.ProtectionParameter {
    }

    private Map<String, Certificate[]> certificateChains;
    private Map<String, PrivateKey> privateKeys;
    private Map<String, Certificate> certificates;
    private String passwordString;

    public JavaKeyStore () {
        this.certificateChains = new HashMap<String, Certificate[]>();
        this.privateKeys = new HashMap<String, PrivateKey>();
        this.certificates = new HashMap<String, Certificate>();
    }

    public String getPasswordString() {
        return passwordString;
    }

    public Map<String, PrivateKey> getPrivateKeys() {
        return privateKeys;
    }

    public Map<String, Certificate[]> getCertificateChains() {
        return certificateChains;
    }

    public Map<String, Certificate> getCertificates () {
        return certificates;
    }

    public void add (PrivateKey privateKey, String alias, Certificate[] certificateChain) {
        getPrivateKeys().put(alias, privateKey);
        getCertificateChains().put(alias, certificateChain);
    }

    public void add (String alias, Certificate certificate) {
        getCertificates().put(alias, certificate);
    }

    public void store (String filename) throws EncryptionException {
        FileOutputStream fileOutputStream = null;

        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            addPrivateKeys(keyStore, getPrivateKeys(), getCertificateChains(), getPasswordString());
            addCertificates(keyStore, getCertificates());
            fileOutputStream = new FileOutputStream(filename);
            keyStore.store(fileOutputStream, getPasswordString().toCharArray());
        } catch (IOException|GeneralSecurityException e) {
            throw new EncryptionException("Exception trying to write keystore", e);
        } finally {
            Utils.closeIgnoreExceptions(fileOutputStream);
        }
    }

    public static void addPrivateKeys(KeyStore keyStore, Map<String, PrivateKey> privateKeys,
                                      Map<String, Certificate[]> chains, String passwordString)
            throws KeyStoreException
    {
        for (String alias : privateKeys.keySet()) {
            PrivateKey privateKey = privateKeys.get(alias);
            Certificate[] certificateChain = chains.get(alias);
            java.security.cert.Certificate[] chain = toCertificateChain(certificateChain);
            keyStore.setKeyEntry(alias, privateKey.getSecurityPrivateKey(), passwordString.toCharArray(),
                    chain);
        }
    }

    public static void addCertificates (KeyStore keyStore, Map<String, Certificate> certificates)
            throws KeyStoreException
    {
        for (String alias : certificates.keySet()) {
            Certificate certificate = certificates.get(alias);
            keyStore.setCertificateEntry(alias, certificate.toJscCertificate());
        }
    }

    public static java.security.cert.Certificate[] toCertificateChain(Certificate[] oldChain) {
        java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[oldChain.length];

        for (int index = 0; index < oldChain.length; index++) {
            newChain[index] = oldChain[index].getCertificate();
        }

        return newChain;
    }

    public void load (String filename) throws EncryptionException {
        File file = new File(filename);
        if (!file.exists()) {
            throw new EncryptionException("The file, " + filename + ", does not exist");
        }

        FileInputStream fileInputStream = null;

        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            fileInputStream = new FileInputStream(file);
            keyStore.load(fileInputStream, getPasswordString().toCharArray());
            extract(keyStore);
        } catch (GeneralSecurityException|IOException e) {
            throw new EncryptionException("Exception trying to load keystore, " + filename, e);
        } finally {
            Utils.closeIgnoreExceptions(fileInputStream);
        }
    }

    public void extract(KeyStore keyStore) throws GeneralSecurityException, EncryptionException {
        Enumeration<String> enumeration = keyStore.aliases();
        String alias = enumeration.nextElement();
        while (alias != null) {
            KeyStore.ProtectionParameter protectionParameter = new ObjectProtectionParameter();
            KeyStore.Entry entry = keyStore.getEntry(alias, protectionParameter);

            if (entry instanceof KeyStore.PrivateKeyEntry) {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                processPrivateKeyEntry(alias, privateKeyEntry);
            } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                KeyStore.TrustedCertificateEntry trustedCertificateEntry = (KeyStore.TrustedCertificateEntry) entry;
                processCertificateEntry(alias, trustedCertificateEntry);
            } else {
                throw new EncryptionException("Unrecognized keystore entry, " + alias + ", class = " +
                        entry.getClass().getCanonicalName());
            }
        }
    }

    public void processPrivateKeyEntry (String alias, KeyStore.PrivateKeyEntry privateKeyEntry) {
        java.security.PrivateKey jsPrivateKey = privateKeyEntry.getPrivateKey();
        PrivateKey privateKey = new PrivateKey(jsPrivateKey);
        getPrivateKeys().put(alias, privateKey);

        java.security.cert.Certificate[] chain = privateKeyEntry.getCertificateChain();
        Certificate[] newChain = asCertificateChain (chain);
        getCertificateChains().put(alias, newChain);
    }

    public Certificate[] asCertificateChain (java.security.cert.Certificate[] oldChain) {
        Certificate[] newChain = new Certificate[oldChain.length];

        for (int index = 0; index < oldChain.length; index++) {
            newChain[index] = new Certificate(oldChain[index]);
        }

        return newChain;
    }

    public void processCertificateEntry (String alias, KeyStore.TrustedCertificateEntry trustedCertificateEntry) {
        Certificate certificate = new Certificate(trustedCertificateEntry.getTrustedCertificate());
        getCertificates().put(alias, certificate);
    }
}
