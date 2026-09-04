package kz.edscheck.xml;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import kz.edscheck.domain.Certificate;

record ParsedXmlSignature(
        int index,
        boolean xades,
        boolean detached,
        boolean qualifyingPropertiesPresent,
        boolean signedPropertiesPresent,
        String id,
        String canonicalizationMethod,
        String signatureMethod,
        List<XmlReference> references,
        byte[] signatureValue,
        X509Certificate certificateRaw,
        Certificate certificate,
        Instant signingTime,
        List<SigningCertDigest> signingCertificateV2,
        List<String> forbiddenV1Forms,
        String signatureTimestampCanonicalizationMethod,
        byte[] signatureTimestampToken,
        List<byte[]> ocspValues,
        List<byte[]> crlValues,
        List<X509Certificate> certificateValues) {
}
