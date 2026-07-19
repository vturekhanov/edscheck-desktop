package kz.edscheck.domain;

import java.time.Instant;

public final class Check {
    private final Stage stage;
    private final CheckStatus status;
    private final String detail;
    private final Instant time;
    private final RevocationSource source;
    private final String crlUrl;
    private final Instant revokedAt;
    private final String revokedReason;
    private final Instant validFrom;
    private final boolean online;

    public Check(Stage stage, CheckStatus status) {
        this(stage, status, null, null, null, null, null, null, null);
    }

    public Check(Stage stage, CheckStatus status, String detail) {
        this(stage, status, detail, null, null, null, null, null, null);
    }

    public Check(
            Stage stage, CheckStatus status, String detail, Instant time,
            RevocationSource source, String crlUrl, Instant revokedAt,
            String revokedReason, Instant validFrom) {
        this(stage, status, detail, time, source, crlUrl, revokedAt, revokedReason, validFrom, false);
    }

    public Check(
            Stage stage, CheckStatus status, String detail, Instant time,
            RevocationSource source, String crlUrl, Instant revokedAt,
            String revokedReason, Instant validFrom, boolean online) {
        this.stage = stage;
        this.status = status;
        this.detail = detail;
        this.time = time;
        this.source = source;
        this.crlUrl = crlUrl;
        this.revokedAt = revokedAt;
        this.revokedReason = revokedReason;
        this.validFrom = validFrom;
        this.online = online;
    }

    public Stage stage() {
        return stage;
    }

    public CheckStatus status() {
        return status;
    }

    public String detail() {
        return detail;
    }

    public Instant time() {
        return time;
    }

    public RevocationSource source() {
        return source;
    }

    public String crlUrl() {
        return crlUrl;
    }

    public Instant revokedAt() {
        return revokedAt;
    }

    public String revokedReason() {
        return revokedReason;
    }

    public Instant validFrom() {
        return validFrom;
    }

    public boolean online() {
        return online;
    }

    public Check withValidFrom(Instant newValidFrom) {
        return new Check(stage, status, detail, time, source, crlUrl,
            revokedAt, revokedReason, newValidFrom, online);
    }

    public Check withRevokedAt(Instant newRevokedAt, String newRevokedReason) {
        return new Check(stage, status, detail, time, source, crlUrl,
            newRevokedAt, newRevokedReason, validFrom, online);
    }

    public Check withOnline(boolean newOnline) {
        return new Check(stage, status, detail, time, source, crlUrl,
            revokedAt, revokedReason, validFrom, newOnline);
    }
}
