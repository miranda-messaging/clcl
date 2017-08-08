package com.ltsllc.clcl;

import com.ltsllc.common.util.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * A Java key store.
 *
 * <p>
 *     This class makes bridging the gap from clcl to java.security a little easier.
 * </p>
 *
 * <h3>Attributes</h3>
 * <table border="1">
 *     <tr>
 *         <th>Name</th>
 *         <th>Type</th>
 *         <th>Description</th>
 *     </tr>
 *     <tr>
 *         <td>filename</td>
 *         <td>String</td>
 *         <td>The file name of the JKS file this instance represents.</td>
 *     </tr>
 *     <tr>
 *         <td>certificateChains</td>
 *         <td>Map<String, Certificate[]></td>
 *         <td>A map from the alias for a key, to the certificate chain for that key.</td>
 *     </tr>
 *     <tr>
 *         <td>privateKeys</td>
 *         <td>Map<String, PrivateKey></td>
 *         <td>A map from the alias for a key, to the key itself.</td>
 *     </tr>
 *     <tr>
 *         <td>certificates</td>
 *         <td>Map<String, Certificate></td>
 *         <td>A map from an alias for a certificate, to the certificate itself.</td>
 *     </tr>
 *     <tr>
 *         <td>passwordString</td>
 *         <td>String</td>
 *         <td>The password for the JKS file.</td>
 *     </tr>
 * </table>
 */
public class JavaKeyStore {
    private String filename;
    private Map<String, Certificate[]> certificateChains;
    private Map<String, PrivateKey> privateKeys;
    private Map<String, Certificate> certificates;
    private String passwordString;

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    /**
     * Create an empty instance
     */
    public JavaKeyStore () {
        this.certificateChains = new HashMap<String, Certificate[]>();
        this.privateKeys = new HashMap<String, PrivateKey>();
        this.certificates = new HashMap<String, Certificate>();
    }

    /**
     * Create an instance and initialize it from a JKS file.
     *
     * @param filename The JKS file to use.
     * @param password The password for the JKS file.  This is also used for the passwords for the keys.
     * @throws EncryptionException If there is a problem loading the JKS file.
     */
    public JavaKeyStore (String filename, String password) throws EncryptionException
    {
        initialize(filename, password);
    }

    /**
     * Initialize the instance from a JKS file.
     *
     * <p>
     *     This constructor creates an empty instance and then calls {@link #load()} on it.
     *     This will set the filename and passwordString attributes for the instance.
     * </p>
     *
     * @param filename The JKS file to use.
     * @param password The password for the JKS file.  This is also used for the passwords for the keys.
     * @throws EncryptionException If there is a problem loading the JKS file.
     */
    public void initialize (String filename, String password) throws EncryptionException {
        this.filename = filename;
        this.certificates = new HashMap<String, Certificate>();
        this.certificateChains = new HashMap<String, Certificate[]>();
        this.privateKeys = new HashMap<String, PrivateKey>();
        this.passwordString = password;

        load();
    }

    public String getPasswordString() {
        return passwordString;
    }

    public void setPasswordString(String passwordString) {
        this.passwordString = passwordString;
    }

    public void setCertificates(Map<String, Certificate> certificates) {
        this.certificates = certificates;
    }

    public void setPrivateKeys(Map<String, PrivateKey> privateKeys) {
        this.privateKeys = privateKeys;
    }

    public void setCertificateChains(Map<String, Certificate[]> certificateChains) {
        this.certificateChains = certificateChains;
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

    /**
     * This method adds a key to the instance.
     *
     * @param alias The alias for the key.
     * @param privateKey The key itself.
     * @param certificateChain The certificate chain for the key.  This may be null.
     */
    public void add (String alias, PrivateKey privateKey, Certificate[] certificateChain) {
        getPrivateKeys().put(alias, privateKey);

        if (certificateChain != null)
            getCertificateChains().put(alias, certificateChain);
    }

    public void add (String alias, Certificate certificate) {
        getCertificates().put(alias, certificate);
    }

    public PrivateKey getPrivateKey (String alias) {
        return getPrivateKeys().get(alias);
    }

    /**
     * This method will store the instance in a JKS file determined by the filename attribute.
     *
     * @throws EncryptionException If there is a problem storing the instance.
     */
    public void store () throws EncryptionException {
        FileOutputStream fileOutputStream = null;

        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null,null);
            addPrivateKeysToKeystore(keyStore, getPrivateKeys(), getCertificateChains(), getPasswordString());
            addCertificatesToKeystore(keyStore, getCertificates());
            fileOutputStream = new FileOutputStream(filename);
            keyStore.store(fileOutputStream, getPasswordString().toCharArray());
        } catch (IOException|GeneralSecurityException e) {
            throw new EncryptionException("Exception trying to write keystore", e);
        } finally {
            Utils.closeIgnoreExceptions(fileOutputStream);
        }
    }

    /**
     * This method will add the supplied private keys to the supplied keystore.  All the parameters are
     * expected to be non-null.
     *
     * <p>
     *     Note that the java.security.PrivateKey is stored, not the com.ltsllc.clcl.PrivateKey.
     * </p>
     *
     * @param keyStore The keystore to store the private keys in.
     * @param privateKeys The keys to store.
     * @param chains The chains for the corresponding keys.  If a key does not have a certificate chain,
     *               then there will be no entry in the map.
     * @param passwordString The password to use for all the keys.
     * @throws KeyStoreException If there is a problem storing the keys.
     */
    public static void addPrivateKeysToKeystore (KeyStore keyStore, Map<String, PrivateKey> privateKeys,
                                      Map<String, Certificate[]> chains, String passwordString)
            throws KeyStoreException
    {
        for (String alias : privateKeys.keySet()) {
            PrivateKey privateKey = privateKeys.get(alias);
            Certificate[] certificateChain = chains.get(alias);
            java.security.cert.Certificate[] chain = toJSChain(certificateChain);
            keyStore.setKeyEntry(alias, privateKey.getSecurityPrivateKey(), passwordString.toCharArray(),
                    chain);
        }
    }

    /**
     * This method adds the supplied certificates to the supplied keystore.  All the parameters are expected
     * to be non-null.
     *
     * <p>
     *     Note that the method stores the java.security.cert.X509Certificate in the keystore,
     *     not the com.ltsllc.clcl.Certificate.
     * </p>
     *
     * @param keyStore The keystore to store the certicates in.
     * @param certificates The certificates to store.
     * @throws KeyStoreException If there is a problem storing the certificates.
     */
    public static void addCertificatesToKeystore (KeyStore keyStore, Map<String, Certificate> certificates)
            throws KeyStoreException
    {
        for (String alias : certificates.keySet()) {
            Certificate certificate = certificates.get(alias);
            keyStore.setCertificateEntry(alias, certificate.getCertificate());
        }
    }

    /**
     * Convert an array of com.ltsllc.clcl certificates into java.security.cert
     * certificates.
     *
     * @param oldChain The com.ltsllc.clcl certificates to convert.
     * @return The java.security.cert certificates
     */
    public static java.security.cert.Certificate[] toJSChain(Certificate[] oldChain) {
        java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[oldChain.length];

        for (int index = 0; index < oldChain.length; index++) {
            newChain[index] = oldChain[index].getCertificate();
        }

        return newChain;
    }

    /**
     * 
     * @throws EncryptionException
     */
    public void load () throws EncryptionException {
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

    public void extract(KeyStore keyStore) throws EncryptionException {
        extractKeys(keyStore);
        extractCertificates(keyStore);
        extractChains(keyStore);
    }

    public void extractKeys (KeyStore keyStore) throws EncryptionException {
        try {
            Map<String, PrivateKey> map = new HashMap<String, PrivateKey>();

            Enumeration<String> enumeration = keyStore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();

                java.security.PrivateKey jsPrivateKey = (java.security.PrivateKey) keyStore.getKey(alias, getPasswordString().toCharArray());
                PrivateKey privateKey = new PrivateKey(jsPrivateKey);
                map.put(alias, privateKey);
            }

            this.privateKeys = map;
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Exception trying to load keystore", e);
        }
    }

    public void extractCertificates (KeyStore keyStore) throws EncryptionException {
        try {
            Map<String, Certificate> map = new HashMap<String, Certificate>();

            Enumeration<String> enumeration = keyStore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();

                java.security.cert.X509Certificate jsCertificate = (java.security.cert.X509Certificate) keyStore.getCertificate(alias);
                Certificate certificate = new Certificate(jsCertificate);

                map.put(alias, certificate);
            }

            this.certificates = map;
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Exception trying to extract certificates", e);
        }
    }

    public void extractChains (KeyStore keyStore) throws EncryptionException {
        try {
            Map<String, Certificate[]> map = new HashMap<String, Certificate[]>();

            Enumeration<String> enumeration = keyStore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();

                java.security.cert.Certificate[] certificates = (java.security.cert.Certificate[]) keyStore.getCertificateChain(alias);

                if (certificates != null) {
                    Certificate[] chain = toClclChain(certificates);
                    map.put(alias, chain);
                }
            }

            this.certificateChains = map;
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Exception trying to extract certificate chains", e);
        }
    }

    public Certificate getCertificate (String alias) {
        return getCertificates().get(alias);
    }

    public static Certificate[] toClclChain (java.security.cert.Certificate[] oldChain) {
        if (oldChain == null)
            return null;

        Certificate[] newChain = new Certificate[oldChain.length];

        for (int i = 0; i < oldChain.length; i++) {
            if (!(oldChain[i] instanceof X509Certificate))
                throw new IllegalArgumentException("Certificate is not X509");

            newChain[i] = new Certificate((X509Certificate) oldChain[i]);
        }

        return newChain;
    }
}
