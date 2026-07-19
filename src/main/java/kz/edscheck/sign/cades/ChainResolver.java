package kz.edscheck.sign.cades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import kz.edscheck.online.Online;

public final class ChainResolver {
    private ChainResolver() {
    }

    public static List<X509Certificate> resolveChain(X509Certificate subject) {
        List<X509Certificate> chain = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        X509Certificate current = subject;
        while (true) {
            X509Certificate issuer = Online.loadIssuerCert(current);
            if (issuer == null) {
                break;
            }
            String fp = fingerprint(issuer);
            if (!seen.add(fp)) {
                break; 
            }
            chain.add(issuer);
            if (issuer.getSubjectX500Principal().equals(issuer.getIssuerX500Principal())) {
                break; 
            }
            current = issuer;
        }
        return chain;
    }

    private static String fingerprint(X509Certificate c) {
        try {
            return Base64.getEncoder().encodeToString(c.getEncoded());
        } catch (Exception e) {
            return "";
        }
    }
}
