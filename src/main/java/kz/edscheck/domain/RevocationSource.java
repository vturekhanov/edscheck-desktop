package kz.edscheck.domain;

public enum RevocationSource {
    OCSP_EMBEDDED,
    OCSP_CONTAINER,
    OCSP_EXTERNAL,
    CRL_EMBEDDED,
    CRL_CONTAINER,
    CRL_FILE,
    CRL_REFERENCE;

    public boolean isOcsp() {
        return this == OCSP_EMBEDDED || this == OCSP_CONTAINER || this == OCSP_EXTERNAL;
    }

    public String jsonValue() {
        return name().toLowerCase();
    }
}
