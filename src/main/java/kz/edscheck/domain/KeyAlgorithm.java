package kz.edscheck.domain;

import java.security.cert.X509Certificate;

public enum KeyAlgorithm {
    GOST,
    RSA;

    public String jsonValue() {
        return name().toLowerCase();
    }

    public static KeyAlgorithm of(X509Certificate cert) {
        String name;
        try {
            name = cert.getPublicKey().getAlgorithm();
        } catch (Exception e) {
            return null;
        }
        if (name == null) {
            return null;
        }
        if (name.equals("RSA")) {
            return RSA;
        }
        if (name.contains("GOST")) {
            return GOST;
        }
        return null;
    }
}
