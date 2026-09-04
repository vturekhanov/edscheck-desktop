package kz.edscheck.trust;

import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public final class ActiveBackend {
    private static CryptoBackend current = new KalkanBackend();

    private ActiveBackend() {
    }

    public static void use(CryptoBackend backend) {
        current = backend;
    }

    public static CryptoBackend current() {
        return current;
    }

    public static CertificateFactory x509CertificateFactory() throws NoSuchProviderException, CertificateException {
        return CertificateFactory.getInstance("X.509", current.jceProviderName());
    }
}
