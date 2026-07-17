package kz.edscheck.domain;


public enum CheckStatus {
    PASS,
    FAIL,
    WARN,
    NOT_VERIFIED,
    
    
    
    SKIP;

    public String jsonValue() {
        return name().toLowerCase();
    }
}
