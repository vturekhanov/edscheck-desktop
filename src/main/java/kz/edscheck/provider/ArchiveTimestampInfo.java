package kz.edscheck.provider;

import java.time.Instant;


public record ArchiveTimestampInfo(int count, int legacyCount, Instant genTime) {

    public static ArchiveTimestampInfo none() {
        return new ArchiveTimestampInfo(0, 0, null);
    }
}
