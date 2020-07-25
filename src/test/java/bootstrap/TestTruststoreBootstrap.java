package bootstrap;

import com.ltsllc.clcl.EncryptionException;
import com.ltsllc.miranda.truststore.TruststoreBootstrap;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class TestTruststoreBootstrap {
    public static final String TEST_TRUSTSTORE_FILENAME = "tempCATruststore";
    public static final String TEST_PASSWORD = "whatever";
    public static final String TEST_DISTINGUISED_NAME = "c=United States of America,st=Colorado,l=Denver,o=whatever company,cn=whatever";
    public static final String TEST_CERTIFICATE_FILENAME = "tempCA";

    @Test
    public void testConstructor () throws EncryptionException, GeneralSecurityException, IOException {
        TruststoreBootstrap.create(TEST_TRUSTSTORE_FILENAME, TEST_PASSWORD, TEST_DISTINGUISED_NAME,
                TEST_CERTIFICATE_FILENAME);
        assert (true);
    }
}
