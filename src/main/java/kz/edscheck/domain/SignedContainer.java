package kz.edscheck.domain;

import java.util.List;


public record SignedContainer(
        String sourcePath,
        Encoding encoding,
        int signaturesTotal,
        List<Signature> signatures,
        String containerFormat,
        String documentName,
        String authority) {

    public SignedContainer {
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
        if (containerFormat == null) {
            containerFormat = "cms";
        }
    }

    
    public SignedContainer(
            String sourcePath, Encoding encoding, int signaturesTotal,
            List<Signature> signatures) {
        this(sourcePath, encoding, signaturesTotal, signatures, "cms", null, null);
    }
}
