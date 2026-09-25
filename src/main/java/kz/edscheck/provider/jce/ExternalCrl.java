package kz.edscheck.provider.jce;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import kz.edscheck.trust.ActiveBackend;

public final class ExternalCrl {
    private static final ExternalCrl ABSENT = new ExternalCrl(false, null);

    private final boolean given;
    private final X509CRL crl;

    private ExternalCrl(boolean given, X509CRL crl) {
        this.given = given;
        this.crl = crl;
    }

    public static ExternalCrl load(String crlPath) {
        if (crlPath == null) {
            return ABSENT;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", ActiveBackend.current().jceProviderName());
            try (InputStream in = new FileInputStream(crlPath)) {
                return new ExternalCrl(true, (X509CRL) cf.generateCRL(in));
            }
        } catch (Exception e) {
            return new ExternalCrl(true, null);
        }
    }

    public boolean covers(X509Certificate target) {
        if (!given) {
            return false;
        }
        return crl == null || EmbeddedRevocation.matchesCrl(crl, target);
    }
}
