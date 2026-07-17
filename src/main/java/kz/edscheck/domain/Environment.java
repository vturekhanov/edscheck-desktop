package kz.edscheck.domain;


public enum Environment {
    TEST,
    PROD;

    public String jsonValue() {
        return name().toLowerCase();
    }
}
