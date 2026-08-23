package kz.edscheck.provider.fake;

import java.time.Instant;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.RevocationSource;

public final class FakeScenario {

    static final Instant FAKE_REVOCATION_VALID_FROM_FALLBACK = Instant.parse("2000-01-01T00:00:00Z");
    private static final Instant FAKE_REVOCATION_VALID_UNTIL = Instant.parse("2100-01-01T00:00:00Z");

    public final CheckStatus integrity;
    public final CheckStatus chain;
    public final CheckStatus revocation;
    public final RevocationSource revocationSource;
    public final String revocationDetail;
    public final Instant revocationValidFrom;
    public final Instant revocationValidUntil;
    public final Boolean timestampPresent;
    public final Boolean timestampValid;
    public final String timestampDetail;
    public final Boolean tsaKeyUsageOk;

    public final CheckStatus archiveStatus;
    public final String archiveDetail;

    private FakeScenario(Builder b) {
        this.integrity = b.integrity;
        this.chain = b.chain;
        this.revocation = b.revocation;
        this.revocationSource = b.revocationSource;
        this.revocationDetail = b.revocationDetail;
        this.revocationValidFrom = b.revocationValidFrom;
        this.revocationValidUntil = b.revocationValidUntil;
        this.timestampPresent = b.timestampPresent;
        this.timestampValid = b.timestampValid;
        this.timestampDetail = b.timestampDetail;
        this.tsaKeyUsageOk = b.tsaKeyUsageOk;
        this.archiveStatus = b.archiveStatus;
        this.archiveDetail = b.archiveDetail;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static FakeScenario defaults() {
        return new Builder().build();
    }

    public static final class Builder {
        private CheckStatus integrity = CheckStatus.PASS;
        private CheckStatus chain = CheckStatus.PASS;
        private CheckStatus revocation = CheckStatus.PASS;
        private RevocationSource revocationSource = RevocationSource.OCSP;
        private String revocationDetail;

        private Instant revocationValidFrom;
        private Instant revocationValidUntil = FAKE_REVOCATION_VALID_UNTIL;
        private Boolean timestampPresent;
        private Boolean timestampValid;
        private String timestampDetail;
        private Boolean tsaKeyUsageOk;
        private CheckStatus archiveStatus;
        private String archiveDetail;

        public Builder integrity(CheckStatus v) {
            this.integrity = v;
            return this;
        }

        public Builder chain(CheckStatus v) {
            this.chain = v;
            return this;
        }

        public Builder revocation(CheckStatus v) {
            this.revocation = v;
            return this;
        }

        public Builder revocationSource(RevocationSource v) {
            this.revocationSource = v;
            return this;
        }

        public Builder revocationDetail(String v) {
            this.revocationDetail = v;
            return this;
        }

        public Builder revocationValidFrom(Instant v) {
            this.revocationValidFrom = v;
            return this;
        }

        public Builder revocationValidUntil(Instant v) {
            this.revocationValidUntil = v;
            return this;
        }

        public Builder timestampPresent(Boolean v) {
            this.timestampPresent = v;
            return this;
        }

        public Builder timestampValid(Boolean v) {
            this.timestampValid = v;
            return this;
        }

        public Builder timestampDetail(String v) {
            this.timestampDetail = v;
            return this;
        }

        public Builder tsaKeyUsageOk(Boolean v) {
            this.tsaKeyUsageOk = v;
            return this;
        }

        public Builder archiveStatus(CheckStatus v) {
            this.archiveStatus = v;
            return this;
        }

        public Builder archiveDetail(String v) {
            this.archiveDetail = v;
            return this;
        }

        public FakeScenario build() {
            return new FakeScenario(this);
        }
    }
}
