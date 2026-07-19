package kz.edscheck.trust;

import java.util.Map;

public final class DigestAlgorithms {
    private static final Map<String, String> OID_TO_NAME = Map.of(
        "1.2.398.3.10.1.3.1", "GOST3411",
        "1.2.398.3.10.1.3.2", "GOST3411-2015-256",
        "1.2.398.3.10.1.3.3", "GOST3411-2015-512",
        "1.2.643.2.2.9", "GOSTR341194",
        "2.16.840.1.101.3.4.2.1", "SHA-256",
        "2.16.840.1.101.3.4.2.2", "SHA-384",
        "2.16.840.1.101.3.4.2.3", "SHA-512",
        "1.3.14.3.2.26", "SHA-1");

    private DigestAlgorithms() {
    }

    public static String jceName(String oid) {
        return oid == null ? null : OID_TO_NAME.get(oid);
    }
}
