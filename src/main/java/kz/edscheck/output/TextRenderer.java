package kz.edscheck.output;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.Check;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.KeyAlgorithm;
import kz.edscheck.domain.RevocationSource;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.Signature;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.TimeSource;
import kz.edscheck.domain.Verdict;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;


public final class TextRenderer {
    private static final Map<CheckStatus, String> GLYPH = new HashMap<>();
    static {
        
        
        
        Map<CheckStatus, String> words = new LinkedHashMap<>();
        words.put(CheckStatus.PASS, Messages.get(MsgKey.GLYPH_PASS));
        words.put(CheckStatus.WARN, Messages.get(MsgKey.GLYPH_WARN));
        words.put(CheckStatus.FAIL, Messages.get(MsgKey.GLYPH_FAIL));
        words.put(CheckStatus.SKIP, Messages.get(MsgKey.GLYPH_SKIP));
        int width = words.values().stream().mapToInt(String::length).max().orElse(0);
        words.forEach((status, word) -> GLYPH.put(status, centerPad(word, width)));
        GLYPH.put(CheckStatus.NOT_VERIFIED, GLYPH.get(CheckStatus.FAIL));
    }

    private static String centerPad(String word, int width) {
        int total = width - word.length();
        if (total <= 0) {
            return word;
        }
        int left = total / 2;
        return " ".repeat(left) + word + " ".repeat(total - left);
    }

    private static final Map<Stage, String> STAGE_LABEL = new HashMap<>();
    static {
        STAGE_LABEL.put(Stage.INTEGRITY, Messages.get(MsgKey.STAGE_INTEGRITY));
        STAGE_LABEL.put(Stage.SIGNED_ATTRIBUTES, Messages.get(MsgKey.STAGE_SIGNED_ATTRIBUTES));
        STAGE_LABEL.put(Stage.TIMESTAMP, Messages.get(MsgKey.STAGE_TIMESTAMP));
        STAGE_LABEL.put(Stage.CHAIN, Messages.get(MsgKey.STAGE_CHAIN));
        STAGE_LABEL.put(Stage.KEY_USAGE, Messages.get(MsgKey.STAGE_KEY_USAGE));
        STAGE_LABEL.put(Stage.VALIDITY, Messages.get(MsgKey.STAGE_VALIDITY));
        STAGE_LABEL.put(Stage.REVOCATION, Messages.get(MsgKey.STAGE_REVOCATION));
        STAGE_LABEL.put(Stage.ARCHIVE_TIMESTAMP, Messages.get(MsgKey.STAGE_ARCHIVE_TIMESTAMP));
    }

    private static final Map<KeyAlgorithm, String> ALG_LABEL = new HashMap<>();
    static {
        ALG_LABEL.put(KeyAlgorithm.RSA, Messages.get(MsgKey.KEY_ALG_RSA));
        ALG_LABEL.put(KeyAlgorithm.GOST, Messages.get(MsgKey.KEY_ALG_GOST));
    }

    
    private static final Map<String, String> CA_LABEL = new HashMap<>();
    static {
        CA_LABEL.put("nca", Messages.get(MsgKey.CA_NCA));
        CA_LABEL.put("btsd", Messages.get(MsgKey.CA_BTSD));
        CA_LABEL.put("ucgo", Messages.get(MsgKey.CA_UCGO));
    }

    private static final Map<RevocationSource, String> REV_SOURCE_LABEL = new HashMap<>();
    static {
        REV_SOURCE_LABEL.put(RevocationSource.OCSP, Messages.get(MsgKey.REV_SOURCE_OCSP));
        REV_SOURCE_LABEL.put(RevocationSource.CRL_EMBEDDED,
            Messages.get(MsgKey.REV_SOURCE_CRL_EMBEDDED));
        REV_SOURCE_LABEL.put(RevocationSource.CRL_FILE, Messages.get(MsgKey.REV_SOURCE_CRL_FILE));
        REV_SOURCE_LABEL.put(RevocationSource.CRL_REFERENCE,
            Messages.get(MsgKey.REV_SOURCE_CRL_REFERENCE));
    }

    
    
    private static final Map<String, String> REVOCATION_REASON_LABEL = new HashMap<>();
    static {
        REVOCATION_REASON_LABEL.put("unspecified",
            Messages.get(MsgKey.REVOCATION_REASON_UNSPECIFIED));
        REVOCATION_REASON_LABEL.put("key_compromise",
            Messages.get(MsgKey.REVOCATION_REASON_KEY_COMPROMISE));
        REVOCATION_REASON_LABEL.put("ca_compromise",
            Messages.get(MsgKey.REVOCATION_REASON_CA_COMPROMISE));
        REVOCATION_REASON_LABEL.put("affiliation_changed",
            Messages.get(MsgKey.REVOCATION_REASON_AFFILIATION_CHANGED));
        REVOCATION_REASON_LABEL.put("superseded",
            Messages.get(MsgKey.REVOCATION_REASON_SUPERSEDED));
        REVOCATION_REASON_LABEL.put("cessation_of_operation",
            Messages.get(MsgKey.REVOCATION_REASON_CESSATION_OF_OPERATION));
        REVOCATION_REASON_LABEL.put("certificate_hold",
            Messages.get(MsgKey.REVOCATION_REASON_CERTIFICATE_HOLD));
        REVOCATION_REASON_LABEL.put("remove_from_crl",
            Messages.get(MsgKey.REVOCATION_REASON_REMOVE_FROM_CRL));
        REVOCATION_REASON_LABEL.put("privilege_withdrawn",
            Messages.get(MsgKey.REVOCATION_REASON_PRIVILEGE_WITHDRAWN));
        REVOCATION_REASON_LABEL.put("aa_compromise",
            Messages.get(MsgKey.REVOCATION_REASON_AA_COMPROMISE));
    }

    
    
    
    
    private static final MsgKey[] FIELD_LABELS = {
        MsgKey.LABEL_SIGNER, MsgKey.LABEL_IIN, MsgKey.LABEL_BIN, MsgKey.LABEL_ROLE,
        MsgKey.LABEL_ORGANIZATION, MsgKey.LABEL_CERTIFICATE, MsgKey.LABEL_REFERENCE_TIME,
    };
    private static final int VALUE_COL;
    static {
        int widest = 0;
        for (MsgKey label : FIELD_LABELS) {
            widest = Math.max(widest, ("  " + Messages.get(label) + ":").length());
        }
        VALUE_COL = widest + 2;
    }

    private TextRenderer() {
    }

    public static String render(SignedContainer container, VerificationRequest request) {
        List<String> lines = new ArrayList<>();
        lines.add(Messages.get(MsgKey.TEXT_HEADER));

        boolean mixed = isMixedAuthority(container);
        String caLabel;
        if (mixed) {
            caLabel = Messages.get(MsgKey.CA_MIXED);
        } else {
            String caCode = container.authority() != null ? container.authority() : request.ca();
            caLabel = CA_LABEL.getOrDefault(caCode, caCode);
        }
        lines.add(Messages.get(MsgKey.TEXT_FILE_LINE, container.sourcePath(),
            caLabel, request.env().jsonValue()));

        if ("ddcard".equals(container.containerFormat())) {
            lines.add(container.documentName() != null
                ? Messages.get(MsgKey.TEXT_FORMAT_DDCARD_DOC, container.documentName())
                : Messages.get(MsgKey.TEXT_FORMAT_DDCARD));
        } else if ("detached".equals(container.containerFormat())) {
            lines.add(container.documentName() != null
                ? Messages.get(MsgKey.TEXT_FORMAT_DETACHED_DOC, container.documentName())
                : Messages.get(MsgKey.TEXT_FORMAT_DETACHED));
        }
        lines.add(Messages.get(MsgKey.TEXT_SIGNATURES_TOTAL, container.signaturesTotal()));

        for (Signature sig : container.signatures()) {
            lines.add("");
            lines.addAll(renderSignature(sig, container.signaturesTotal(), mixed));
        }

        return String.join("\n", lines);
    }

    
    private static boolean isMixedAuthority(SignedContainer container) {
        long distinct = container.signatures().stream()
            .map(Signature::authority)
            .filter(a -> a != null)
            .distinct()
            .count();
        return distinct > 1;
    }

    private static String field(MsgKey label, String value) {
        return pad("  " + Messages.get(label) + ":", VALUE_COL) + value;
    }

    private static String pad(String s, int width) {
        if (s.length() >= width) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < width) {
            sb.append(' ');
        }
        return sb.toString();
    }

    private static List<String> renderSignature(Signature sig, int total, boolean mixed) {
        List<String> lines = new ArrayList<>();
        String header = Messages.get(MsgKey.TEXT_SIGNATURE_HEADER, sig.index() + 1, total);
        lines.add(pad(header, VALUE_COL) + verdictLabel(sig));

        
        
        
        if (mixed) {
            lines.add(field(MsgKey.LABEL_CA,
                sig.authority() != null
                    ? CA_LABEL.getOrDefault(sig.authority(), sig.authority())
                    : Messages.get(MsgKey.CA_UNKNOWN)));
        }

        Certificate signer = sig.signer();
        lines.add(field(MsgKey.LABEL_SIGNER,
            nonEmpty(signer.commonName()) ? signer.commonName() : Messages.get(MsgKey.TEXT_NO_VALUE)));
        if (nonEmpty(signer.iin())) {
            lines.add(field(MsgKey.LABEL_IIN, signer.iin()));
        }
        if (nonEmpty(signer.bin())) {
            lines.add(field(MsgKey.LABEL_BIN, signer.bin()));
        }
        if (signer.subjectRoles() != null && !signer.subjectRoles().isEmpty()) {
            lines.add(field(MsgKey.LABEL_ROLE, String.join(" / ", signer.subjectRoles())));
        }
        if (nonEmpty(signer.organization())) {
            lines.add(field(MsgKey.LABEL_ORGANIZATION, signer.organization()));
        }
        lines.addAll(certLines(sig));
        lines.add(field(MsgKey.LABEL_REFERENCE_TIME, fmtDt(sig.referenceTime().value())
            + " (" + refSourceLabel(sig.referenceTime().source()) + ")"));
        lines.add("  " + Messages.get(MsgKey.LABEL_CHECKS) + ":");
        for (Check check : sig.checks()) {
            lines.addAll(renderCheck(check));
        }
        return lines;
    }

    private static String verdictLabel(Signature sig) {
        if (sig.verdict() == Verdict.GENUINE) {
            return sig.warnings().isEmpty()
                ? Messages.get(MsgKey.VERDICT_GENUINE)
                : Messages.get(MsgKey.VERDICT_GENUINE_WARNINGS);
        }
        return Messages.get(MsgKey.VERDICT_INVALID);
    }

    
    private static List<String> certLines(Signature sig) {
        Certificate c = sig.signer();
        List<String> rows = new ArrayList<>();
        if (nonEmpty(c.serialNumber())) {
            rows.add(Messages.get(MsgKey.CERT_SERIAL, c.serialNumber()));
        }
        if (nonEmpty(c.issuer())) {
            rows.add(Messages.get(MsgKey.CERT_ISSUER, c.issuer()));
        }
        List<String> tail = new ArrayList<>();
        if (c.keyAlgorithm() != null) {
            tail.add(ALG_LABEL.getOrDefault(c.keyAlgorithm(), c.keyAlgorithm().jsonValue()));
        }
        String validity = validityPart(c);
        if (!validity.isEmpty()) {
            tail.add(validity);
        }
        if (!tail.isEmpty()) {
            rows.add(String.join(", ", tail));
        }
        if (rows.isEmpty()) {
            rows.add(Messages.get(MsgKey.TEXT_NO_VALUE));
        }
        String indent = " ".repeat(VALUE_COL);
        List<String> out = new ArrayList<>();
        out.add(field(MsgKey.LABEL_CERTIFICATE, rows.get(0)));
        for (int i = 1; i < rows.size(); i++) {
            out.add(indent + rows.get(i));
        }
        return out;
    }

    private static String validityPart(Certificate c) {
        if (c.notBefore() != null && c.notAfter() != null) {
            return Messages.get(MsgKey.CERT_VALIDITY_FROM_TO,
                fmtDt(c.notBefore()), fmtDt(c.notAfter()));
        }
        if (c.notAfter() != null) {
            return Messages.get(MsgKey.CERT_VALIDITY_TO, fmtDt(c.notAfter()));
        }
        if (c.notBefore() != null) {
            return Messages.get(MsgKey.CERT_VALIDITY_FROM, fmtDt(c.notBefore()));
        }
        return "";
    }

    private static List<String> renderCheck(Check check) {
        String label = STAGE_LABEL.getOrDefault(check.stage(), check.stage().jsonValue());
        String suffix = checkSuffix(check);
        String onlineMark = check.online() ? " " + Messages.get(MsgKey.CHECK_ONLINE_MARK) : "";
        List<String> result = new ArrayList<>();
        result.add("    [" + GLYPH.get(check.status()) + "]  " + label + suffix + onlineMark);
        if (check.stage() == Stage.REVOCATION && check.crlUrl() != null) {
            result.add("            " + Messages.get(MsgKey.CHECK_CRL_HINT, check.crlUrl()));
        }
        return result;
    }

    private static String checkSuffix(Check check) {
        String detail = detail(check);
        if (check.stage() == Stage.TIMESTAMP) {
            if (check.status() == CheckStatus.PASS) {
                return " — " + Messages.get(MsgKey.CHECK_TIMESTAMP_VALID);
            }
            return detail != null ? " — " + detail : "";
        }
        if (check.stage() == Stage.ARCHIVE_TIMESTAMP) {
            if (check.status() == CheckStatus.PASS) {
                String text = detail != null
                    ? detail
                    : Messages.get(MsgKey.CHECK_ARCHIVE_TIMESTAMP_VALID);
                if (check.time() != null) {
                    text += ", " + fmtDt(check.time());
                }
                return " — " + text;
            }
            return detail != null ? " — " + detail : "";
        }
        if (check.stage() == Stage.REVOCATION) {
            return revocationSuffix(check);
        }
        if (check.stage() == Stage.KEY_USAGE && check.status() == CheckStatus.PASS) {
            return " " + Messages.get(MsgKey.CHECK_KEY_USAGE_PASS);
        }
        return detail != null ? " — " + detail : "";
    }

    private static String revocationSuffix(Check check) {
        String detail = detail(check);
        String source = check.source() != null ? REV_SOURCE_LABEL.get(check.source()) : null;
        String text;
        if (check.status() == CheckStatus.PASS) {
            text = source != null
                ? Messages.get(MsgKey.CHECK_REVOCATION_NOT_REVOKED_SRC, source)
                : Messages.get(MsgKey.CHECK_REVOCATION_NOT_REVOKED);
        } else if (check.status() == CheckStatus.WARN) {
            text = detail != null
                ? detail
                : Messages.get(MsgKey.CHECK_REVOCATION_REVOKED_AFTER_REF);
        } else if (check.status() == CheckStatus.FAIL && check.detail() == null) {
            text = source != null
                ? Messages.get(MsgKey.CHECK_REVOCATION_REVOKED_SRC, source)
                : Messages.get(MsgKey.CHECK_REVOCATION_REVOKED);
        } else {
            List<String> parts = new ArrayList<>();
            if (check.status() == CheckStatus.NOT_VERIFIED) {
                parts.add(Messages.get(MsgKey.CHECK_REVOCATION_NOT_VERIFIED));
            }
            if (detail != null) {
                parts.add(detail);
            }
            text = String.join(": ", parts);
        }

        
        
        
        if (check.validFrom() != null) {
            text += " (thisUpdate " + fmtDt(check.validFrom()) + ")";
        }

        
        
        if (check.revokedAt() != null) {
            String paren = fmtDt(check.revokedAt());
            if (check.revokedReason() != null) {
                paren += ", " + REVOCATION_REASON_LABEL.getOrDefault(
                    check.revokedReason(), check.revokedReason());
            }
            text += " (" + paren + ")";
        }
        return text.isEmpty() ? "" : " — " + text;
    }

    private static String refSourceLabel(TimeSource source) {
        return source == TimeSource.TIMESTAMP
            ? Messages.get(MsgKey.TIME_SOURCE_TIMESTAMP)
            : Messages.get(MsgKey.TIME_SOURCE_CURRENT);
    }

    private static String detail(Check check) {
        return NativeDates.localize(check.detail());
    }

    private static final DateTimeFormatter DT_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx", Locale.ROOT);

    
    private static String fmtDt(Instant value) {
        return value.atZone(ZoneId.systemDefault()).format(DT_FMT);
    }

    private static boolean nonEmpty(String s) {
        return s != null && !s.isEmpty();
    }
}
