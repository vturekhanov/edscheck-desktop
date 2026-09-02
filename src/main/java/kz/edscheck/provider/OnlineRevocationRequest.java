package kz.edscheck.provider;

import java.security.cert.X509Certificate;

import kz.edscheck.domain.Stage;

public record OnlineRevocationRequest(
        X509Certificate target, X509Certificate issuer, String digestOid, String label,
        int signerIndex, Stage stage) {
}
