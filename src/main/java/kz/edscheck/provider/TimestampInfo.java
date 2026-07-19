package kz.edscheck.provider;

import java.time.Instant;

public record TimestampInfo(
        boolean present,
        Boolean valid,
        Instant genTime,
        String detail,
        Boolean tsaKeyUsageOk,
        StageOutcome tsaOcsp) {

    public static TimestampInfo absent() {
        return new TimestampInfo(false, null, null, null, null, null);
    }

    public static TimestampInfo of(boolean present, Boolean valid, Instant genTime) {
        return new TimestampInfo(present, valid, genTime, null, null, null);
    }
}
