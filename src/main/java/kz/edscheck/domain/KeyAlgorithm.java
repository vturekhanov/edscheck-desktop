package kz.edscheck.domain;


public enum KeyAlgorithm {
    GOST,
    RSA;

    public String jsonValue() {
        return name().toLowerCase();
    }
}
