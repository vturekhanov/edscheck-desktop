package kz.edscheck.provider;

import java.time.Instant;
import java.util.List;

public record ArchiveMarkOutcome(
        int position,
        String parseError,
        Instant genTime,
        Boolean sigOk,
        Boolean chainOk,
        Boolean tsaValidityOk,
        Boolean tsaEkuOk,
        String hashFailure,
        StageOutcome ownRevocation,
        Instant tsaCertNotAfter,
        List<CaRevocationFact> intermediateCaRevocations) {

    public ArchiveMarkOutcome {
        intermediateCaRevocations =
            intermediateCaRevocations == null ? List.of() : List.copyOf(intermediateCaRevocations);
    }
}
