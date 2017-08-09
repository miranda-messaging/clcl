package com.ltsllc.clcl;

import com.ltsllc.clcl.test.EncryptionTestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;

public class TestKey extends EncryptionTestCase {
    public static final String TEST_ALGORITHM = "AES";
    public static final String TEST_MESSAGE = "TEST";
    public static final String TEST_PASSWORD = "whatever";

    @Before
    public void setup () throws Exception {
        KeyPair keyPair = KeyPair.newKeys();
        setPublicKey(keyPair.getPublicKey());
        setPrivateKey(keyPair.getPrivateKey());
    }

    public static boolean containsBouncyCastleProvider (Provider[] providers) {
        for (Provider provider : providers) {
            if (provider instanceof BouncyCastleProvider)
                return true;
        }

        return false;
    }

    @Test
    public void testCheckProviders () {
        getPublicKey().checkProviders();

        Provider[] providers = Security.getProviders();
        assert (containsBouncyCastleProvider(providers));
    }

    // also tests encrypt(byte[]) decrypt(EncryptedMessage) and decrypt(byte[])
    @Test
    public void testEncrypt () throws Exception {
        EncryptedMessage encryptedMessage = getPublicKey().encrypt(TEST_ALGORITHM, TEST_MESSAGE.getBytes());
        byte[] plainText = getPrivateKey().decrypt(encryptedMessage);
        String decryptedMessage = new String (plainText);

        assert (TEST_MESSAGE.equals(decryptedMessage));
    }

    // also tests decryptString
    @Test
    public void testEncryptString () throws Exception {
        String cipertextString = getPublicKey().encryptString(TEST_MESSAGE);
        String plaintextString = getPrivateKey().decryptString(cipertextString);
        assert (plaintextString.equals(TEST_MESSAGE));
    }

    @Test
    public void testToPem () throws Exception {
        String pem = getPublicKey().toPem();
        PublicKey publicKey = PublicKey.fromPEM(pem);
        assert (publicKey.equals(getPublicKey()));
    }


    @Test
    public void testToPemWithPassword () throws Exception {
        String pem = getPublicKey().toPem(TEST_PASSWORD);
        PublicKey publicKey = PublicKey.fromPEM(pem, TEST_PASSWORD);
        assert(getPublicKey().equals(publicKey));
    }

}
