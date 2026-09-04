package kz.edscheck.trust;

public interface CryptoBackend {

    String engineName();

    String jceProviderName();

    boolean available();

    void ensureRegistered() throws KalkanJarException, LibraryJarException;
}
