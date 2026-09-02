package kz.edscheck.provider;

import java.time.Instant;
import java.util.List;

public record TimestampInfo(
        boolean present,
        Boolean valid,
        Instant genTime,
        String detail,
        Boolean tsaKeyUsageOk,
        StageOutcome tsaOcsp,
        Instant tsaCertNotAfter,
        List<CaRevocationFact> intermediateCaRevocations) {

    public TimestampInfo {
        intermediateCaRevocations =
            intermediateCaRevocations == null ? List.of() : List.copyOf(intermediateCaRevocations);
    }

    public TimestampInfo(
            boolean present, Boolean valid, Instant genTime, String detail,
            Boolean tsaKeyUsageOk, StageOutcome tsaOcsp, Instant tsaCertNotAfter) {
        this(present, valid, genTime, detail, tsaKeyUsageOk, tsaOcsp, tsaCertNotAfter, List.of());
    }

    public TimestampInfo(
            boolean present, Boolean valid, Instant genTime, String detail,
            Boolean tsaKeyUsageOk, StageOutcome tsaOcsp) {
        this(present, valid, genTime, detail, tsaKeyUsageOk, tsaOcsp, null, List.of());
    }

    public static TimestampInfo absent() {
        return new TimestampInfo(false, null, null, null, null, null, null, List.of());
    }

    public static TimestampInfo of(boolean present, Boolean valid, Instant genTime) {
        return new TimestampInfo(present, valid, genTime, null, null, null, null, List.of());
    }
}
