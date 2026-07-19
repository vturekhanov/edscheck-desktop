package kz.edscheck.provider;

import java.util.List;
import kz.edscheck.domain.Encoding;

public record ProviderResult(Encoding encoding, List<SignerVerification> signers, String authority) {

    public ProviderResult {
        signers = signers == null ? List.of() : List.copyOf(signers);
    }

    public ProviderResult(Encoding encoding, List<SignerVerification> signers) {
        this(encoding, signers, null);
    }

    public int signaturesTotal() {
        return signers.size();
    }
}
