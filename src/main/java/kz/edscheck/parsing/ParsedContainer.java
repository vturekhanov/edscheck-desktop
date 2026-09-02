package kz.edscheck.parsing;

import java.security.cert.X509Certificate;
import java.util.List;
import kz.edscheck.domain.Encoding;

public record ParsedContainer(
        Encoding encoding, String cadesLevel, List<ParsedSigner> signers,
        List<X509Certificate> containerCerts, List<byte[]> crlBlobs) {

    public ParsedContainer {
        containerCerts = containerCerts == null ? List.of() : List.copyOf(containerCerts);
        crlBlobs = crlBlobs == null ? List.of() : List.copyOf(crlBlobs);
    }

    public int signaturesTotal() {
        return signers.size();
    }
}
