package kz.edscheck.trust;

import java.security.Security;

public final class KalkanProviderRegistrar {
    private KalkanProviderRegistrar() {
    }

    public static void ensureSecurityProviderRegistered() {
        if (Security.getProvider("KALKAN") == null) {
            Security.addProvider(new kz.gov.pki.kalkan.jce.provider.KalkanProvider());
        }
    }
}
