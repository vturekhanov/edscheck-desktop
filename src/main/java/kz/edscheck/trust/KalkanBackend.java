package kz.edscheck.trust;

public final class KalkanBackend implements CryptoBackend {
    @Override
    public String engineName() {

        return "kalkan-java";
    }

    @Override
    public String jceProviderName() {
        return "KALKAN";
    }

    @Override
    public boolean available() {
        return KalkanJar.classAvailable();
    }

    @Override
    public void ensureRegistered() throws KalkanJarException {
        KalkanJar.resolveAndVerify();
        KalkanProviderRegistrar.ensureSecurityProviderRegistered();
    }
}
