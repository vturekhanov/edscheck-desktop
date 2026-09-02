package kz.edscheck.rules;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.Check;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.RevocationSource;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.TimeSource;
import kz.edscheck.domain.Verdict;
import kz.edscheck.domain.Warnings;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.ArchiveTs;
import kz.edscheck.provider.ArchiveMarkOutcome;
import kz.edscheck.provider.ArchiveTimestampInfo;
import kz.edscheck.provider.CaRevocationFact;
import kz.edscheck.provider.KeyUsageInfo;
import kz.edscheck.provider.RevocationCombine;
import kz.edscheck.provider.SignerVerification;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.TimestampInfo;

public final class Rules {
    private Rules() {
    }

    public record CheckAndWarnings(Check check, List<String> warnings) {
    }

    public static kz.edscheck.domain.ReferenceTime computeReferenceTime(
            TimestampInfo timestamp, PolicyProfile policy) {
        if (timestamp.present()
                && Boolean.TRUE.equals(timestamp.valid())
                && !Boolean.FALSE.equals(timestamp.tsaKeyUsageOk())
                && timestamp.genTime() != null
                && !tsaOcspWindowViolated(timestamp, policy)) {
            return new kz.edscheck.domain.ReferenceTime(timestamp.genTime(), TimeSource.TIMESTAMP);
        }
        return new kz.edscheck.domain.ReferenceTime(Instant.now(), TimeSource.CURRENT);
    }

    private static boolean tsaOcspWindowViolated(TimestampInfo timestamp, PolicyProfile policy) {
        if (timestamp.genTime() == null) {
            return false;
        }
        return revocationWindowViolated(
            timestamp.tsaOcsp(), timestamp.genTime(), timestamp.tsaCertNotAfter(), policy);
    }

    private static boolean revocationWindowViolated(
            StageOutcome outcome, Instant referenceTime, Instant certNotAfter, PolicyProfile policy) {
        if (outcome == null) {
            return false;
        }
        Check probe = new Check(Stage.REVOCATION, CheckStatus.PASS, null, null, outcome.source(),
            null, null, null);
        Check afterPeriod = applyRevocationPeriod(
            probe, outcome, referenceTime, Instant.now(), certNotAfter, policy);
        if (afterPeriod.status() != CheckStatus.PASS) {
            return true;
        }
        if (outcome.source() == null || !outcome.source().isOcsp()) {
            return false;
        }
        Instant thisUpdate = outcome.validFrom();
        return thisUpdate != null && thisUpdate.isBefore(referenceTime.minus(OCSP_SIGNING_LOWER_BOUND));
    }

    private static boolean ocspWindowViolated(
            Instant thisUpdate, Instant validUntil, Instant referenceTime, Duration ocspMaxAge) {
        if (thisUpdate == null || ocspMaxAge == null) {
            return false;
        }
        Instant lower = thisUpdate.minus(ocspMaxAge);
        Instant upper = validUntil != null ? validUntil : thisUpdate.plus(ocspMaxAge);
        return referenceTime.isBefore(lower) || referenceTime.isAfter(upper);
    }

    public static CheckAndWarnings timestampCheck(TimestampInfo timestamp, PolicyProfile policy) {
        List<String> warnings = new ArrayList<>();
        if (!timestamp.present()) {
            if (policy.requireTimestamp()) {
                return new CheckAndWarnings(
                    new Check(Stage.TIMESTAMP, CheckStatus.FAIL,
                        Messages.get(MsgKey.RULES_TIMESTAMP_REQUIRED_ABSENT)),
                    warnings);
            }
            warnings.add(Warnings.TIMESTAMP_ABSENT);
            return new CheckAndWarnings(
                new Check(Stage.TIMESTAMP, CheckStatus.WARN,
                    Messages.get(MsgKey.RULES_TIMESTAMP_ABSENT_WARN)),
                warnings);
        }
        if (Boolean.TRUE.equals(timestamp.valid())) {

            if (Boolean.FALSE.equals(timestamp.tsaKeyUsageOk())) {
                return new CheckAndWarnings(
                    new Check(Stage.TIMESTAMP, CheckStatus.FAIL,
                        Messages.get(MsgKey.RULES_TIMESTAMP_TSA_NO_EKU),
                        timestamp.genTime(), null, null, null, null),
                    warnings);
            }

            if (tsaOcspWindowViolated(timestamp, policy)) {
                return new CheckAndWarnings(
                    new Check(Stage.TIMESTAMP, CheckStatus.FAIL,
                        Messages.get(MsgKey.RULES_TIMESTAMP_TSA_OCSP_WINDOW),
                        timestamp.genTime(), null, null, null, null),
                    warnings);
            }

            StageOutcome caDecision = decideIntermediateCaRevocation(
                timestamp.intermediateCaRevocations(), timestamp.genTime(), policy);
            if (caDecision.status() == CheckStatus.NOT_VERIFIED) {
                return new CheckAndWarnings(
                    new Check(Stage.TIMESTAMP, CheckStatus.NOT_VERIFIED,
                        Messages.get(MsgKey.RULES_TIMESTAMP_TSA_INTERMEDIATE_CA_REVOCATION_ABSENT),
                        timestamp.genTime(), null, null, null, null),
                    warnings);
            }
            if (caDecision.status() != CheckStatus.PASS) {
                return new CheckAndWarnings(
                    new Check(Stage.TIMESTAMP, CheckStatus.FAIL,
                        Messages.get(
                            MsgKey.RULES_TIMESTAMP_TSA_INTERMEDIATE_CA_REVOCATION_FAILED, caDecision.detail()),
                        timestamp.genTime(), null, null, null, null),
                    warnings);
            }
            return new CheckAndWarnings(
                new Check(Stage.TIMESTAMP, CheckStatus.PASS, null,
                    timestamp.genTime(), null, null, null, null),
                warnings);
        }
        return new CheckAndWarnings(
            new Check(Stage.TIMESTAMP, CheckStatus.FAIL,
                timestamp.detail() != null
                    ? timestamp.detail()
                    : Messages.get(MsgKey.RULES_TIMESTAMP_INVALID),
                timestamp.genTime(), null, null, null, null),
            warnings);
    }

    private static final Map<String, String> BB_ATTR_WARNING = Map.of(
        "content-type", Warnings.CONTENT_TYPE_ABSENT,
        "message-digest", Warnings.MESSAGE_DIGEST_ABSENT,
        "signing-time", Warnings.SIGNING_TIME_ABSENT,
        "signing-certificate-v2", Warnings.SIGNING_CERTIFICATE_V2_ABSENT);

    public static CheckAndWarnings signedAttrsCheck(List<String> missingBbAttrs, PolicyProfile policy) {
        List<String> warnings = new ArrayList<>();
        if (missingBbAttrs.isEmpty()) {
            return new CheckAndWarnings(new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.PASS), warnings);
        }
        String joined = String.join(", ", missingBbAttrs);
        if (policy.requireBbAttrs()) {
            return new CheckAndWarnings(
                new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.FAIL,
                    Messages.get(MsgKey.RULES_SIGNED_ATTRS_REQUIRED_MISSING, joined)),
                warnings);
        }
        for (String name : missingBbAttrs) {
            String code = BB_ATTR_WARNING.get(name);
            if (code != null) {
                warnings.add(code);
            }
        }
        return new CheckAndWarnings(
            new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.WARN,
                Messages.get(MsgKey.RULES_SIGNED_ATTRS_MISSING, joined)),
            warnings);
    }

    public static CheckAndWarnings archiveTimestampCheck(
            ArchiveTimestampInfo info, StageOutcome outcome, List<ArchiveMarkOutcome> markOutcomes,
            PolicyProfile policy) {
        List<String> warnings = new ArrayList<>();
        if (info.legacyCount() > 0) {
            warnings.add(Warnings.ARCHIVE_TS_FORMAT_UNSUPPORTED);
        }
        if (info.count() == 0) {
            if (info.legacyCount() > 0) {
                return new CheckAndWarnings(
                    new Check(Stage.ARCHIVE_TIMESTAMP, CheckStatus.NOT_VERIFIED,
                        Messages.get(MsgKey.RULES_ARCHIVE_TS_LEGACY_UNSUPPORTED)),
                    warnings);
            }
            return new CheckAndWarnings(
                new Check(Stage.ARCHIVE_TIMESTAMP, CheckStatus.SKIP,
                    Messages.get(MsgKey.RULES_ARCHIVE_TS_NONE)),
                warnings);
        }
        if (markOutcomes != null && !markOutcomes.isEmpty()) {
            List<ArchiveTs.Failure> failures = new ArrayList<>();
            for (ArchiveMarkOutcome mo : markOutcomes) {
                String revocationFailure = archiveMarkRevocationFailure(mo, policy);
                String failure = ArchiveTs.markFailure(mo.parseError(), mo.sigOk(), mo.chainOk(), mo.chainOk(),
                    mo.tsaValidityOk(), mo.tsaEkuOk(), revocationFailure, mo.hashFailure());
                if (failure != null) {
                    failures.add(new ArchiveTs.Failure(mo.position(), failure));
                }
            }
            ArchiveTs.Combined combined = ArchiveTs.combineResults(markOutcomes.size(), failures);
            return new CheckAndWarnings(
                new Check(Stage.ARCHIVE_TIMESTAMP, combined.ok() ? CheckStatus.PASS : CheckStatus.FAIL,
                    combined.detail(), info.genTime(), null, null, null, null),
                warnings);
        }
        if (outcome == null) {
            return new CheckAndWarnings(
                new Check(Stage.ARCHIVE_TIMESTAMP, CheckStatus.NOT_VERIFIED,
                    Messages.get(MsgKey.RULES_ARCHIVE_TS_PROVIDER_UNSUPPORTED),
                    info.genTime(), null, null, null, null),
                warnings);
        }
        return new CheckAndWarnings(
            new Check(Stage.ARCHIVE_TIMESTAMP, outcome.status(), outcome.detail(),
                info.genTime(), null, null, null, null),
            warnings);
    }

    private static String archiveMarkRevocationFailure(ArchiveMarkOutcome mo, PolicyProfile policy) {
        Instant refTime = mo.genTime();
        StageOutcome own = mo.ownRevocation();
        if (own != null) {
            if (own.status() == CheckStatus.NOT_VERIFIED) {
                return Messages.get(MsgKey.RULES_ARCHIVE_TS_TSA_REVOCATION_ABSENT);
            }
            if (own.status() != CheckStatus.PASS) {
                return Messages.get(MsgKey.RULES_ARCHIVE_TS_TSA_REVOCATION_FAILED, own.detail());
            }
            if (refTime != null && revocationWindowViolated(own, refTime, mo.tsaCertNotAfter(), policy)) {
                return Messages.get(MsgKey.RULES_ARCHIVE_TS_TSA_REVOCATION_FAILED,
                    Messages.get(MsgKey.RULES_CHAIN_INTERMEDIATE_CA_WINDOW_EXPIRED));
            }
        }
        if (refTime == null) {
            return null;
        }
        StageOutcome caDecision = decideIntermediateCaRevocation(mo.intermediateCaRevocations(), refTime, policy);
        if (caDecision.status() == CheckStatus.NOT_VERIFIED) {
            return Messages.get(MsgKey.RULES_ARCHIVE_TS_TSA_INTERMEDIATE_CA_REVOCATION_ABSENT);
        }
        if (caDecision.status() != CheckStatus.PASS) {
            return Messages.get(MsgKey.RULES_ARCHIVE_TS_TSA_INTERMEDIATE_CA_REVOCATION_FAILED, caDecision.detail());
        }
        return null;
    }

    public static Check decideValidity(Instant referenceTime, Certificate cert, PolicyProfile policy) {
        return decideValidity(referenceTime, cert, policy, null);
    }

    public static Check decideValidity(
            Instant referenceTime, Certificate cert, PolicyProfile policy, List<Certificate> chain) {
        List<Certificate> all = new ArrayList<>();
        all.add(cert);
        if (chain != null) {
            all.addAll(chain);
        }
        for (Certificate c : all) {
            if (c.notBefore() == null || c.notAfter() == null) {
                return new Check(Stage.VALIDITY, CheckStatus.NOT_VERIFIED,
                    Messages.get(MsgKey.RULES_VALIDITY_UNDETERMINED, certLabel(c)));
            }
            if (referenceTime.isBefore(c.notBefore())) {
                return new Check(Stage.VALIDITY, CheckStatus.FAIL,
                    Messages.get(MsgKey.RULES_VALIDITY_BEFORE_NOT_BEFORE, certLabel(c)));
            }
            if (referenceTime.isAfter(c.notAfter())) {
                return new Check(Stage.VALIDITY, CheckStatus.FAIL,
                    Messages.get(MsgKey.RULES_VALIDITY_EXPIRED, certLabel(c)));
            }
        }
        return new Check(Stage.VALIDITY, CheckStatus.PASS);
    }

    private static String certLabel(Certificate cert) {
        if (cert.commonName() != null) {
            return cert.commonName();
        }
        if (cert.serialNumber() != null) {
            return cert.serialNumber();
        }
        return Messages.get(MsgKey.LABEL_CERTIFICATE);
    }

    static StageOutcome decideIntermediateCaRevocation(
            List<CaRevocationFact> facts, Instant referenceTime, PolicyProfile policy) {
        if (facts.isEmpty()) {
            return new StageOutcome(CheckStatus.PASS);
        }
        List<StageOutcome> afterWindow = new ArrayList<>();
        boolean anyMissing = false;
        for (CaRevocationFact fact : facts) {
            StageOutcome outcome = fact.outcome();
            if (outcome.status() == CheckStatus.NOT_VERIFIED) {
                anyMissing = true;
                continue;
            }
            if (outcome.status() == CheckStatus.PASS
                    && revocationWindowViolated(outcome, referenceTime, fact.certNotAfter(), policy)) {
                outcome = StageOutcome.of(CheckStatus.FAIL)
                    .source(outcome.source())
                    .validFrom(outcome.validFrom())
                    .validUntil(outcome.validUntil())
                    .detail(Messages.get(MsgKey.RULES_CHAIN_INTERMEDIATE_CA_WINDOW_EXPIRED))
                    .build();
            }
            afterWindow.add(outcome);
        }
        if (!afterWindow.isEmpty()) {
            StageOutcome combined = RevocationCombine.combineByRevokedWins(afterWindow);
            if (combined.status() == CheckStatus.FAIL && combined.revokedAt() != null) {
                return combined;
            }
        }
        if (anyMissing) {
            return new StageOutcome(CheckStatus.NOT_VERIFIED);
        }
        return RevocationCombine.combineByRevokedWins(afterWindow);
    }

    public static Check applyIntermediateCaRevocation(
            Check chain, List<CaRevocationFact> facts, Instant referenceTime, PolicyProfile policy) {
        if (chain.status() != CheckStatus.PASS || facts.isEmpty()) {
            return chain;
        }
        StageOutcome decision = decideIntermediateCaRevocation(facts, referenceTime, policy);
        if (decision.status() == CheckStatus.NOT_VERIFIED) {
            return new Check(Stage.CHAIN, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_CHAIN_INTERMEDIATE_CA_REVOCATION_ABSENT));
        }
        if (decision.status() != CheckStatus.PASS) {
            return new Check(Stage.CHAIN, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_CHAIN_INTERMEDIATE_CA_REVOCATION_FAILED, decision.detail()));
        }
        return chain;
    }

    public static Check applyRevocationPeriod(
            Check check, StageOutcome outcome, Instant referenceTime, Instant checkTime,
            Instant certNotAfter, PolicyProfile policy) {
        if (check.status() != CheckStatus.PASS || outcome == null) {
            return check;
        }

        boolean isCrl = check.source() != null && !check.source().isOcsp();
        String labelSource = isCrl
            ? Messages.get(MsgKey.RULES_REVOCATION_SOURCE_CRL)
            : Messages.get(MsgKey.RULES_REVOCATION_SOURCE_OCSP_RECEIPT);

        Instant thisUpdate = outcome.validFrom();
        if (thisUpdate == null) {
            return new Check(Stage.REVOCATION, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_REVOCATION_NO_THIS_UPDATE, labelSource),
                null, check.source(), null, null, null);
        }
        Instant nextUpdate = outcome.validUntil();

        if (isCrl) {
            return applyCrlPeriod(check, thisUpdate, nextUpdate, referenceTime, checkTime, certNotAfter);
        }
        if (nextUpdate == null) {
            if (policy.ocspMaxAge() == null) {
                return check.withValidFrom(thisUpdate);
            }
            nextUpdate = thisUpdate.plus(policy.ocspMaxAge());
        }
        if (referenceTime.isAfter(nextUpdate)) {

            return ocspWindowFailCheck(check, thisUpdate);
        }
        return check.withValidFrom(thisUpdate);
    }

    private static Check applyCrlPeriod(
            Check check, Instant thisUpdate, Instant nextUpdate, Instant referenceTime,
            Instant checkTime, Instant certNotAfter) {
        if (nextUpdate == null) {
            return new Check(Stage.REVOCATION, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_REVOCATION_CRL_NO_NEXT_UPDATE),
                null, check.source(), null, null, null);
        }
        if (thisUpdate.isAfter(nextUpdate)) {
            return new Check(Stage.REVOCATION, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_REVOCATION_CRL_THIS_UPDATE_AFTER_NEXT_UPDATE),
                null, check.source(), null, null, null);
        }
        if (thisUpdate.isAfter(checkTime)) {
            return new Check(Stage.REVOCATION, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_REVOCATION_CRL_THIS_UPDATE_IN_FUTURE),
                null, check.source(), null, null, null);
        }
        if (certNotAfter != null && thisUpdate.isAfter(certNotAfter)) {
            return new Check(Stage.REVOCATION, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_REVOCATION_CRL_AFTER_CERT_EXPIRY),
                null, check.source(), null, null, null);
        }
        if (referenceTime.isAfter(nextUpdate)) {
            return new Check(Stage.REVOCATION, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_REVOCATION_CRL_INVALID_NOW),
                null, check.source(), null, null, null);
        }
        return check.withValidFrom(thisUpdate);
    }

    private static Check ocspWindowFailCheck(Check check, Instant thisUpdate) {
        return new Check(
            check.stage(), CheckStatus.FAIL,
            Messages.get(MsgKey.RULES_REVOCATION_OCSP_WINDOW_VIOLATED),
            null, check.source(), check.revokedAt(), check.revokedReason(),
            thisUpdate);
    }

    public static CheckAndWarnings applyRevocationDate(Check check, StageOutcome outcome) {
        if (check.status() != CheckStatus.FAIL || outcome == null) {
            return new CheckAndWarnings(check, List.of());
        }
        Instant revokedAt = outcome.revokedAt();
        if (revokedAt == null) {
            return new CheckAndWarnings(check, List.of());
        }
        return new CheckAndWarnings(check.withRevokedAt(revokedAt, outcome.revokedReason()), List.of());
    }

    private static final Duration OCSP_SIGNING_LOWER_BOUND = Duration.ofSeconds(10);

    public static Check applyOcspSigningWindow(
            Check check, StageOutcome outcome, Instant referenceTime, PolicyProfile policy) {
        if (outcome == null || check.source() == null || !check.source().isOcsp()) {
            return check;
        }
        Instant thisUpdate = outcome.validFrom();
        if (thisUpdate == null) {
            return check;
        }
        if (policy.ddcard()) {
            if (policy.ocspMaxAge() == null) {
                return check;
            }
            if (!ocspWindowViolated(thisUpdate, outcome.validUntil(), referenceTime, policy.ocspMaxAge())) {
                return check;
            }
            return ocspWindowFailCheck(check, thisUpdate);
        }
        if (thisUpdate.isBefore(referenceTime.minus(OCSP_SIGNING_LOWER_BOUND))) {
            return ocspWindowFailCheck(check, thisUpdate);
        }
        return check;
    }

    public static Check decideKeyUsage(KeyUsageInfo keyUsage, PolicyProfile policy) {
        var usages = keyUsage.usages();
        if (usages.isEmpty()) {
            return new Check(Stage.KEY_USAGE, CheckStatus.NOT_VERIFIED,
                Messages.get(MsgKey.RULES_KEY_USAGE_NO_DATA));
        }
        boolean hasNonRepudiation = usages.contains("non_repudiation");
        boolean hasDigitalSignature = usages.contains("digital_signature");

        if (policy.requireNonRepudiation()) {
            if (hasNonRepudiation) {
                return new Check(Stage.KEY_USAGE, CheckStatus.PASS);
            }
            return new Check(Stage.KEY_USAGE, CheckStatus.FAIL,
                Messages.get(MsgKey.RULES_KEY_USAGE_NO_NON_REPUDIATION));
        }

        if (hasNonRepudiation || hasDigitalSignature) {
            return new Check(Stage.KEY_USAGE, CheckStatus.PASS);
        }
        return new Check(Stage.KEY_USAGE, CheckStatus.FAIL,
            Messages.get(MsgKey.RULES_KEY_USAGE_NOT_FOR_SIGNING));
    }

    public static Verdict computeVerdict(List<Check> checks) {
        Map<Stage, CheckStatus> statusByStage = new EnumMap<>(Stage.class);
        for (Check c : checks) {
            statusByStage.put(c.stage(), c.status());
        }
        for (Stage stage : Stage.MANDATORY_STAGES) {
            if (statusByStage.get(stage) != CheckStatus.PASS) {
                return Verdict.INVALID;
            }
        }
        if (statusByStage.get(Stage.TIMESTAMP) == CheckStatus.FAIL) {
            return Verdict.INVALID;
        }
        if (statusByStage.get(Stage.ARCHIVE_TIMESTAMP) == CheckStatus.FAIL) {
            return Verdict.INVALID;
        }

        if (statusByStage.get(Stage.SIGNED_ATTRIBUTES) == CheckStatus.FAIL) {
            return Verdict.INVALID;
        }
        return Verdict.GENUINE;
    }

    public static Check outcomeToCheck(Stage stage, StageOutcome outcome) {
        return new Check(stage, outcome.status(), outcome.detail(), null,
            outcome.source(), null, null, null);
    }
}
