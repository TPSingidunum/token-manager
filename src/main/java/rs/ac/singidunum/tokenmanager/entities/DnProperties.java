package rs.ac.singidunum.tokenmanager.entities;

public class DnProperties {
    private String commonName;
    private String orgUnit;
    private String org;
    private String locality;
    private String state;
    private String country;

    public DnProperties(String commonName, String orgUnit, String org, String locality, String state, String country) {
        this.commonName = commonName;
        this.orgUnit = orgUnit;
        this.org = org;
        this.locality = locality;
        this.state = state;
        this.country = country;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrgUnit() {
        return orgUnit;
    }

    public void setOrgUnit(String orgUnit) {
        this.orgUnit = orgUnit;
    }

    public String getOrg() {
        return org;
    }

    public void setOrg(String org) {
        this.org = org;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String toX500Principal() {
        return String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s",commonName, orgUnit, org, locality, state, country);
    }
}