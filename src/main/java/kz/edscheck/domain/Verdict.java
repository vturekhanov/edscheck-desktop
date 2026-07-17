package kz.edscheck.domain;


public enum Verdict {
    GENUINE,
    INVALID;

    
    public String jsonValue() {
        return name().toLowerCase();
    }
}
