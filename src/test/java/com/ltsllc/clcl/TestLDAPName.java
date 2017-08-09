package com.ltsllc.clcl;

import com.ltsllc.clcl.test.EncryptionTestCase;
import org.junit.Before;
import org.junit.Test;

public class TestLDAPName extends EncryptionTestCase {
    private LDAPName ldapName;

    public LDAPName getLdapName() {
        return ldapName;
    }

    public void setLdapName(LDAPName ldapName) {
        this.ldapName = ldapName;
    }

    @Before
    public void setup () {
        this.ldapName = new LDAPName("cn=John Doe");
    }

    @Test
    public void testEquals () {
        LDAPName other = new LDAPName("cn=John Doe");
        LDAPName different = new LDAPName("c=US");
        assert (getLdapName().equals(other));
        assert (!getLdapName().equals(different));
    }
}
