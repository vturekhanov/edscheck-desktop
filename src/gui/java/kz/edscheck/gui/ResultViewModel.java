package kz.edscheck.gui;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import kz.edscheck.app.RunResult;
import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.Check;
import kz.edscheck.domain.KeyAlgorithm;
import kz.edscheck.domain.ReferenceTime;
import kz.edscheck.domain.RevocationSource;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.Signature;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.Verdict;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.output.NativeDates;


public record ResultViewModel(
        String filePath,
        String caLabel,
        String envLabel,
        String containerFormat,
        String documentName,
        int signaturesTotal,
        boolean mixedAuthority,
        List<SignatureView> signatures) {

    
    public record SignatureView(
            int index,
            int total,
            Verdict verdict,
            String verdictLabel,
            String caLabel,
            Certificate signer,
            String signerDisplayName,
            String keyAlgorithmLabel,
            ReferenceTime referenceTime,
            String referenceTimeSourceLabel,
            List<String> warnings,
            List<CheckView> checks) {
    }

    
    public record CheckView(
            Check check,
            String stageLabel,
            String sourceLabel,
            String revokedReasonLabel) {
    }

    public static ResultViewModel from(RunResult result) {
        SignedContainer container = result.container();
        VerificationRequest request = result.request();

        boolean mixed = isMixedAuthority(container);
        String caLabel;
        if (mixed) {
            caLabel = Messages.get(MsgKey.CA_MIXED);
        } else {
            String caCode = container.authority() != null ? container.authority() : request.ca();
            caLabel = CA_LABEL.getOrDefault(caCode, caCode);
        }

        List<SignatureView> signatures = new ArrayList<>();
        for (Signature sig : container.signatures()) {
            signatures.add(signatureView(sig, container.signaturesTotal()));
        }

        return new ResultViewModel(
            container.sourcePath(),
            caLabel,
            request.env().jsonValue(),
            container.containerFormat(),
            container.documentName(),
            container.signaturesTotal(),
            mixed,
            signatures);
    }

    
    private static boolean isMixedAuthority(SignedContainer container) {
        long distinct = container.signatures().stream()
            .map(Signature::authority)
            .filter(a -> a != null)
            .distinct()
            .count();
        return distinct > 1;
    }

    private static SignatureView signatureView(Signature sig, int total) {
        Certificate signer = sig.signer();
        String signerDisplayName = nonEmpty(signer.commonName())
            ? signer.commonName() : Messages.get(MsgKey.TEXT_NO_VALUE);
        String keyAlgorithmLabel = signer.keyAlgorithm() != null
            ? ALG_LABEL.getOrDefault(signer.keyAlgorithm(), signer.keyAlgorithm().jsonValue())
            : null;

        String caLabel = sig.authority() != null
            ? CA_LABEL.getOrDefault(sig.authority(), sig.authority())
            : Messages.get(MsgKey.CA_UNKNOWN);

        List<CheckView> checks = new ArrayList<>();
        for (Check check : sig.checks()) {
            checks.add(checkView(check));
        }

        return new SignatureView(
            sig.index(),
            total,
            sig.verdict(),
            verdictLabel(sig),
            caLabel,
            signer,
            signerDisplayName,
            keyAlgorithmLabel,
            sig.referenceTime(),
            refSourceLabel(sig.referenceTime()),
            List.copyOf(sig.warnings()),
            checks);
    }

    private static String verdictLabel(Signature sig) {
        if (sig.verdict() == Verdict.GENUINE) {
            return sig.warnings().isEmpty()
                ? Messages.get(MsgKey.VERDICT_GENUINE)
                : Messages.get(MsgKey.VERDICT_GENUINE_WARNINGS);
        }
        return Messages.get(MsgKey.VERDICT_INVALID);
    }

    private static CheckView checkView(Check check) {
        String stageLabel = STAGE_LABEL.getOrDefault(check.stage(), check.stage().jsonValue());
        String sourceLabel = check.source() != null ? REV_SOURCE_LABEL.get(check.source()) : null;
        String revokedReasonLabel = check.revokedReason() != null
            ? REVOCATION_REASON_LABEL.getOrDefault(check.revokedReason(), check.revokedReason())
            : null;
        
        
        
        
        
        String localizedDetail = NativeDates.localize(check.detail());
        Check normalized = Objects.equals(localizedDetail, check.detail())
            ? check
            : new Check(check.stage(), check.status(), localizedDetail, check.time(), check.source(),
                check.crlUrl(), check.revokedAt(), check.revokedReason(), check.validFrom(), check.online());
        return new CheckView(normalized, stageLabel, sourceLabel, revokedReasonLabel);
    }

    private static String refSourceLabel(ReferenceTime referenceTime) {
        return switch (referenceTime.source()) {
            case TIMESTAMP -> Messages.get(MsgKey.TIME_SOURCE_TIMESTAMP);
            case CURRENT -> Messages.get(MsgKey.TIME_SOURCE_CURRENT);
        };
    }

    private static boolean nonEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    private static final Map<Stage, String> STAGE_LABEL = Map.of(
        Stage.INTEGRITY, Messages.get(MsgKey.STAGE_INTEGRITY),
        Stage.SIGNED_ATTRIBUTES, Messages.get(MsgKey.STAGE_SIGNED_ATTRIBUTES),
        Stage.TIMESTAMP, Messages.get(MsgKey.STAGE_TIMESTAMP),
        Stage.CHAIN, Messages.get(MsgKey.STAGE_CHAIN),
        Stage.KEY_USAGE, Messages.get(MsgKey.STAGE_KEY_USAGE),
        Stage.VALIDITY, Messages.get(MsgKey.STAGE_VALIDITY),
        Stage.REVOCATION, Messages.get(MsgKey.STAGE_REVOCATION),
        Stage.ARCHIVE_TIMESTAMP, Messages.get(MsgKey.STAGE_ARCHIVE_TIMESTAMP));

    private static final Map<KeyAlgorithm, String> ALG_LABEL = Map.of(
        KeyAlgorithm.RSA, Messages.get(MsgKey.KEY_ALG_RSA),
        KeyAlgorithm.GOST, Messages.get(MsgKey.KEY_ALG_GOST));

    private static final Map<String, String> CA_LABEL = Map.of(
        "nca", Messages.get(MsgKey.CA_NCA),
        "btsd", Messages.get(MsgKey.CA_BTSD),
        "ucgo", Messages.get(MsgKey.CA_UCGO));

    private static final Map<RevocationSource, String> REV_SOURCE_LABEL = Map.of(
        RevocationSource.OCSP, Messages.get(MsgKey.REV_SOURCE_OCSP),
        RevocationSource.CRL_EMBEDDED, Messages.get(MsgKey.REV_SOURCE_CRL_EMBEDDED),
        RevocationSource.CRL_FILE, Messages.get(MsgKey.REV_SOURCE_CRL_FILE),
        RevocationSource.CRL_REFERENCE, Messages.get(MsgKey.REV_SOURCE_CRL_REFERENCE));

    private static final Map<String, String> REVOCATION_REASON_LABEL = Map.of(
        "unspecified", Messages.get(MsgKey.REVOCATION_REASON_UNSPECIFIED),
        "key_compromise", Messages.get(MsgKey.REVOCATION_REASON_KEY_COMPROMISE),
        "ca_compromise", Messages.get(MsgKey.REVOCATION_REASON_CA_COMPROMISE),
        "affiliation_changed", Messages.get(MsgKey.REVOCATION_REASON_AFFILIATION_CHANGED),
        "superseded", Messages.get(MsgKey.REVOCATION_REASON_SUPERSEDED),
        "cessation_of_operation", Messages.get(MsgKey.REVOCATION_REASON_CESSATION_OF_OPERATION),
        "certificate_hold", Messages.get(MsgKey.REVOCATION_REASON_CERTIFICATE_HOLD),
        "remove_from_crl", Messages.get(MsgKey.REVOCATION_REASON_REMOVE_FROM_CRL),
        "privilege_withdrawn", Messages.get(MsgKey.REVOCATION_REASON_PRIVILEGE_WITHDRAWN),
        "aa_compromise", Messages.get(MsgKey.REVOCATION_REASON_AA_COMPROMISE));
}
