package kz.edscheck.provider;

import java.time.Instant;
import java.util.List;
import kz.edscheck.domain.CheckStatus;

public final class RevocationCombine {
    private RevocationCombine() {
    }

    public static StageOutcome combineByRevokedWins(List<StageOutcome> outcomes) {
        for (StageOutcome o : outcomes) {
            if (o.status() == CheckStatus.FAIL && o.revokedAt() != null) {
                return o;
            }
        }
        StageOutcome latestGood = null;
        for (StageOutcome o : outcomes) {
            if (o.status() != CheckStatus.PASS) {
                continue;
            }
            if (latestGood == null || isAfterOrLatestUnknown(o.validFrom(), latestGood.validFrom())) {
                latestGood = o;
            }
        }
        return latestGood != null ? latestGood : outcomes.get(0);
    }

    private static boolean isAfterOrLatestUnknown(Instant candidate, Instant current) {
        if (candidate == null) {
            return false;
        }
        return current == null || candidate.isAfter(current);
    }
}
