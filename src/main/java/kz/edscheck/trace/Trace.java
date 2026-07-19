package kz.edscheck.trace;

public interface Trace {
    Trace NONE = message -> { };

    void v(String message);
}
