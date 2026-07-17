package kz.edscheck.parsing;

import java.security.cert.X509Certificate;
import java.util.List;
import kz.edscheck.domain.Encoding;


public record ParsedContainer(
        Encoding encoding, String cadesLevel, List<ParsedSigner> signers,
        List<X509Certificate> containerCerts) {

    public ParsedContainer {
        containerCerts = containerCerts == null ? List.of() : List.copyOf(containerCerts);
    }

    public int signaturesTotal() {
        return signers.size();
    }
}
