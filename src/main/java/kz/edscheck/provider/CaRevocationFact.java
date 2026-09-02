package kz.edscheck.provider;

import java.time.Instant;

public record CaRevocationFact(StageOutcome outcome, Instant certNotAfter) {
}
