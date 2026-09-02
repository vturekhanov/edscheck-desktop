package kz.edscheck.provider;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.Stage;

public final class SignerVerification {
    private int index;
    private final Certificate certificate;
    private final KeyUsageInfo keyUsage;
    private final TimestampInfo timestamp;
    private final ArchiveTimestampInfo archive;
    private final Map<Stage, StageOutcome> outcomes;
    private final List<Certificate> chain;
    private final List<String> warnings;

    private final List<String> missingBbAttrs;

    private final String authority;

    private final List<CaRevocationFact> intermediateCaRevocations;

    private final List<ArchiveMarkOutcome> archiveMarkOutcomes;

    public SignerVerification(
            int index, Certificate certificate, KeyUsageInfo keyUsage,
            TimestampInfo timestamp, ArchiveTimestampInfo archive,
            Map<Stage, StageOutcome> outcomes, List<Certificate> chain,
            List<String> warnings, List<String> missingBbAttrs) {
        this(index, certificate, keyUsage, timestamp, archive, outcomes, chain, warnings,
            missingBbAttrs, null);
    }

    public SignerVerification(
            int index, Certificate certificate, KeyUsageInfo keyUsage,
            TimestampInfo timestamp, ArchiveTimestampInfo archive,
            Map<Stage, StageOutcome> outcomes, List<Certificate> chain,
            List<String> warnings, List<String> missingBbAttrs, String authority) {
        this(index, certificate, keyUsage, timestamp, archive, outcomes, chain, warnings,
            missingBbAttrs, authority, null);
    }

    public SignerVerification(
            int index, Certificate certificate, KeyUsageInfo keyUsage,
            TimestampInfo timestamp, ArchiveTimestampInfo archive,
            Map<Stage, StageOutcome> outcomes, List<Certificate> chain,
            List<String> warnings, List<String> missingBbAttrs, String authority,
            List<CaRevocationFact> intermediateCaRevocations) {
        this(index, certificate, keyUsage, timestamp, archive, outcomes, chain, warnings,
            missingBbAttrs, authority, intermediateCaRevocations, null);
    }

    public SignerVerification(
            int index, Certificate certificate, KeyUsageInfo keyUsage,
            TimestampInfo timestamp, ArchiveTimestampInfo archive,
            Map<Stage, StageOutcome> outcomes, List<Certificate> chain,
            List<String> warnings, List<String> missingBbAttrs, String authority,
            List<CaRevocationFact> intermediateCaRevocations,
            List<ArchiveMarkOutcome> archiveMarkOutcomes) {
        this.index = index;
        this.certificate = certificate;
        this.keyUsage = keyUsage == null ? new KeyUsageInfo() : keyUsage;
        this.timestamp = timestamp == null ? TimestampInfo.absent() : timestamp;
        this.archive = archive == null ? ArchiveTimestampInfo.none() : archive;
        this.outcomes = outcomes == null ? new EnumMap<>(Stage.class) : new EnumMap<>(outcomes);
        this.chain = chain == null ? List.of() : List.copyOf(chain);
        this.warnings = warnings == null ? List.of() : List.copyOf(warnings);
        this.missingBbAttrs = missingBbAttrs == null ? List.of() : List.copyOf(missingBbAttrs);
        this.authority = authority;
        this.intermediateCaRevocations =
            intermediateCaRevocations == null ? List.of() : List.copyOf(intermediateCaRevocations);
        this.archiveMarkOutcomes =
            archiveMarkOutcomes == null ? List.of() : List.copyOf(archiveMarkOutcomes);
    }

    public int index() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public Certificate certificate() {
        return certificate;
    }

    public KeyUsageInfo keyUsage() {
        return keyUsage;
    }

    public TimestampInfo timestamp() {
        return timestamp;
    }

    public ArchiveTimestampInfo archive() {
        return archive;
    }

    public Map<Stage, StageOutcome> outcomes() {
        return outcomes;
    }

    public List<Certificate> chain() {
        return chain;
    }

    public List<String> warnings() {
        return warnings;
    }

    public List<String> missingBbAttrs() {
        return missingBbAttrs;
    }

    public String authority() {
        return authority;
    }

    public List<CaRevocationFact> intermediateCaRevocations() {
        return intermediateCaRevocations;
    }

    public List<ArchiveMarkOutcome> archiveMarkOutcomes() {
        return archiveMarkOutcomes;
    }
}
