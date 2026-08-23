package kz.edscheck.xml;

import java.security.cert.X509Certificate;

import kz.edscheck.domain.Certificate;

record EsfInvoice(
        byte[] signedBytes,
        byte[] signatureValue,
        X509Certificate certificateRaw,
        Certificate certificate) {
}
