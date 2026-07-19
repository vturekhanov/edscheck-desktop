package kz.edscheck.domain;

import java.util.List;

public enum Stage {
    INTEGRITY,

    SIGNED_ATTRIBUTES,
    TIMESTAMP,
    CHAIN,
    KEY_USAGE,
    VALIDITY,
    REVOCATION,

    ARCHIVE_TIMESTAMP;

    public String jsonValue() {
        return name().toLowerCase();
    }

    public static final List<Stage> MANDATORY_STAGES =
        List.of(INTEGRITY, CHAIN, KEY_USAGE, VALIDITY, REVOCATION);
}
