package com.ltsllc.clcl;

import com.ltsllc.clcl.test.EncryptionTestCase;
import org.junit.Before;
import org.junit.Test;

public class TestKeyPair extends EncryptionTestCase {
    public static final String TEST_PASSWORD = "whatever";
    @Before
    public void setup () throws EncryptionException {
        creaateKeyPair();
    }

    @Test
    public void testNewKeys () {
        assert (null != getKeyPair());
    }

    // also tests fromPem
    @Test
    public void testToPemNoPassword () throws EncryptionException{
        String pem = getKeyPair().toPem();
        KeyPair keyPair = KeyPair.fromPem(pem);
        assert (getKeyPair().equals(keyPair));
    }

    @Test
    public void testToPemWithPassword () throws EncryptionException {
        String pem = getKeyPair().toPem(TEST_PASSWORD);
        KeyPair keyPair = KeyPair.fromPem(pem, TEST_PASSWORD);
        assert (getKeyPair().equals(keyPair));
    }
}
