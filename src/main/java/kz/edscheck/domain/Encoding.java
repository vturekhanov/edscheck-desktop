package kz.edscheck.domain;

public enum Encoding {
    DER,
    BASE64;

    public String jsonValue() {
        return name().toLowerCase();
    }
}
