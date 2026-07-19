package kz.edscheck.domain;

public enum RevocationSource {
    OCSP,
    CRL_EMBEDDED,
    CRL_FILE,
    CRL_REFERENCE;

    public String jsonValue() {
        return name().toLowerCase();
    }
}
