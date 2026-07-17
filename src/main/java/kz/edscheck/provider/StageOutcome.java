package kz.edscheck.provider;

import java.time.Instant;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.RevocationSource;


public final class StageOutcome {
    private final CheckStatus status;
    private final String detail;
    private final RevocationSource source;
    private final String crlUrl;
    private final Instant validFrom;
    private final Instant validUntil;
    private final Instant revokedAt;
    private final String revokedReason;

    public StageOutcome(CheckStatus status) {
        this(status, null, null, null, null, null, null, null);
    }

    public StageOutcome(CheckStatus status, String detail) {
        this(status, detail, null, null, null, null, null, null);
    }

    public StageOutcome(
            CheckStatus status, String detail, RevocationSource source, String crlUrl,
            Instant validFrom, Instant validUntil, Instant revokedAt, String revokedReason) {
        this.status = status;
        this.detail = detail;
        this.source = source;
        this.crlUrl = crlUrl;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
        this.revokedAt = revokedAt;
        this.revokedReason = revokedReason;
    }

    public CheckStatus status() {
        return status;
    }

    public String detail() {
        return detail;
    }

    public RevocationSource source() {
        return source;
    }

    public String crlUrl() {
        return crlUrl;
    }

    public Instant validFrom() {
        return validFrom;
    }

    public Instant validUntil() {
        return validUntil;
    }

    public Instant revokedAt() {
        return revokedAt;
    }

    public String revokedReason() {
        return revokedReason;
    }

    
    public static final class Builder {
        private final CheckStatus status;
        private String detail;
        private RevocationSource source;
        private String crlUrl;
        private Instant validFrom;
        private Instant validUntil;
        private Instant revokedAt;
        private String revokedReason;

        public Builder(CheckStatus status) {
            this.status = status;
        }

        public Builder detail(String v) {
            this.detail = v;
            return this;
        }

        public Builder source(RevocationSource v) {
            this.source = v;
            return this;
        }

        public Builder crlUrl(String v) {
            this.crlUrl = v;
            return this;
        }

        public Builder validFrom(Instant v) {
            this.validFrom = v;
            return this;
        }

        public Builder validUntil(Instant v) {
            this.validUntil = v;
            return this;
        }

        public Builder revokedAt(Instant v) {
            this.revokedAt = v;
            return this;
        }

        public Builder revokedReason(String v) {
            this.revokedReason = v;
            return this;
        }

        public StageOutcome build() {
            return new StageOutcome(status, detail, source, crlUrl, validFrom, validUntil,
                revokedAt, revokedReason);
        }
    }

    public static Builder of(CheckStatus status) {
        return new Builder(status);
    }
}
