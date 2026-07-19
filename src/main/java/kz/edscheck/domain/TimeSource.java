package kz.edscheck.domain;

public enum TimeSource {
    TIMESTAMP,
    CURRENT;

    public String jsonValue() {
        return name().toLowerCase();
    }
}
