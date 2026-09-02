package kz.edscheck.parsing;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import kz.edscheck.domain.Certificate;
import kz.edscheck.provider.ArchiveTimestampInfo;
import kz.edscheck.provider.KeyUsageInfo;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;

public record ParsedSigner(
        int index,
        Certificate certificate,
        KeyUsageInfo keyUsage,
        Instant signingTime,
        Instant tstGenTime,
        boolean hasTimestamp,
        boolean hasRevocationValues,
        Boolean tsaTimestampingEkuOk,
        List<Certificate> chain,
        ArchiveTimestampInfo archive,
        X509Certificate signerCertRaw,
        String signingCertHashAlg,
        byte[] signingCertHash,
        X509Certificate tsaCertRaw,
        List<X509Certificate> tsaCertsRaw,
        byte[] tstTokenDer,
        byte[] signatureValue,
        String tstImprintAlg,
        byte[] tstImprintHash,
        List<ArchiveTs.ParsedArchiveTimestamp> archiveMarks,
        SignerInformation signerInfo,
        List<String> missingBbAttrs,
        List<byte[]> tstCrlBlobs) {
}
