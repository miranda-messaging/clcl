package com.ltsllc.clcl;

/**
 * An LDAP Distinguished Name.
 *
 * <p>
 *     The class sets the Country Code, State, City, Company,
 *     and Division to {@link #UNKNOWN}, but the client must set the Name
 *     to some value.
 * </p>
 *
 * <h3>Attributes</h3>
 * <table width="1">
 *     <tr>
 *         <th>Name</th>
 *         <th>Type</th>
 *         <th>Description</th>
 *     </tr>
 *     <tr>
 *         <td>countryCode</td>
 *         <td>String</td>
 *         <td>The 2-letter LDAP counrty code</td>
 *     </tr>
 *     <tr>
 *         <td>state</td>
 *         <td>String</td>
 *         <td>The state or province for the object</td>
 *     </tr>
 *     <tr>
 *         <td>city</td>
 *         <td>String</td>
 *         <td>The city ("locality" in LDAP speak) of the object</td>
 *     </tr>
 *     <tr>
 *         <td>company</td>
 *         <td>String</td>
 *         <td>The company or organization for the object</td>
 *     </tr>
 *     <tr>
 *         <td>division</td>
 *         <td>String</td>
 *         <td>The division within the company or organization of the object.  For example, "development".</td>
 *     </tr>
 *     <tr>
 *         <td>name</td>
 *         <td>String</td>
 *         <td>
 *             The "common name" of the person (if this object is for a person) or the
 *             fully qualified domain name (if this object is associated with a system)
 *             of the thing the object is associated with.
 *         </td>
 *     </tr>
 * </table>
 */
public class DistinguishedName {
    public static final String UNKNOWN = "Unknown";

    private String countryCode = UNKNOWN;
    private String state = UNKNOWN;
    private String city = UNKNOWN;
    private String company = UNKNOWN;
    private String division = UNKNOWN;

    private String name;

    public DistinguishedName() {
    }

    public DistinguishedName (DistinguishedName dn) {
        this.countryCode = dn.getCountryCode();
        this.state = dn.getState();
        this.city = dn.getCity();
        this.company = dn.getCompany();
        this.division = dn.getDivision();
        this.name = dn.getName();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDivision() {

        return division;
    }

    public void setDivision(String division) {
        this.division = division;
    }

    public String getCompany() {

        return company;
    }

    public void setCompany(String company) {
        this.company = company;
    }

    public String getCity() {

        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getState() {

        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCountryCode() {

        return countryCode;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    /**
     * Create a string, suitable for use as an {@link sun.security.x509.X500Name}
     * for the object.
     *
     * @return The string described above.
     */
    public String toString () {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("c=");
        stringBuilder.append(getCountryCode());
        stringBuilder.append("st=");
        stringBuilder.append(getState());
        stringBuilder.append("l=");
        stringBuilder.append(getCity());
        stringBuilder.append("o=");
        stringBuilder.append(getCompany());
        stringBuilder.append("ou=");
        stringBuilder.append(getDivision());
        stringBuilder.append("cn=");
        stringBuilder.append(getName());

        return stringBuilder.toString();
    }
}
