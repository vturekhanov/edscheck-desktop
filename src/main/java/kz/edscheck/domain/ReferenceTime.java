package kz.edscheck.domain;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public record ReferenceTime(Instant value, TimeSource source) {

    public static Instant truncate(Instant time) {
        return time == null ? null : time.truncatedTo(ChronoUnit.SECONDS);
    }
}
