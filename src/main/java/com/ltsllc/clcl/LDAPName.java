package com.ltsllc.clcl;

public class LDAPName {
    private String key;
    private String value;

    public LDAPName (String name) {
        initialize(name);
    }

    public String getValue() {
        return value;
    }

    public String getKey() {
        return key;
    }

    public void initialize (String name) {
        String fields[] = name.split("=");
        this.key = fields[0].trim();
        this.value = fields[1].trim();
    }

    public String toString () {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(getKey());
        stringBuilder.append('=');
        stringBuilder.append(getValue());

        return stringBuilder.toString();
    }

    public boolean equals (Object o) {
        if (o == null || !(o instanceof LDAPName))
            return false;

        LDAPName other = (LDAPName) o;
        return getKey().equals(other.getKey()) && getValue().equals(other.getValue());
    }
}
