package kz.edscheck.domain;

import java.time.Instant;

public record ReferenceTime(Instant value, TimeSource source) {
}
