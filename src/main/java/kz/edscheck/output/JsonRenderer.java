package kz.edscheck.output;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.Check;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.Signature;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.Version;

public final class JsonRenderer {
    private JsonRenderer() {
    }

    public static String render(SignedContainer container, VerificationRequest request) {
        return JsonWriter.write(buildPayload(container, request));
    }

    public static Map<String, Object> buildPayload(
            SignedContainer container, VerificationRequest request) {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("path", container.sourcePath());
        input.put("encoding", container.encoding().jsonValue());
        input.put("format", container.containerFormat());
        if (container.documentName() != null) {
            input.put("document", container.documentName());
        }

        boolean mixed = isMixedAuthority(container);
        Object caField = mixed ? null : (container.authority() != null ? container.authority() : request.ca());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("tool", "eds-check");
        payload.put("version", Version.VALUE);
        payload.put("ca", caField);
        payload.put("env", request.env().jsonValue());
        payload.put("input", input);
        payload.put("signatures_total", container.signaturesTotal());
        List<Object> signatures = new ArrayList<>();
        for (Signature sig : container.signatures()) {
            signatures.add(signature(sig, mixed));
        }
        payload.put("signatures", signatures);
        return payload;
    }

    private static boolean isMixedAuthority(SignedContainer container) {
        long distinct = container.signatures().stream()
            .map(Signature::authority)
            .filter(a -> a != null)
            .distinct()
            .count();
        return distinct > 1;
    }

    private static Map<String, Object> signature(Signature sig, boolean mixed) {
        Map<String, Object> referenceTime = new LinkedHashMap<>();
        referenceTime.put("value", iso(sig.referenceTime().value()));
        referenceTime.put("source", sig.referenceTime().source().jsonValue());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("index", sig.index());
        out.put("verdict", sig.verdict().jsonValue());

        if (mixed) {
            out.put("ca", sig.authority());
        }
        out.put("warnings", new ArrayList<Object>(sig.warnings()));
        out.put("reference_time", referenceTime);
        out.put("signer", signer(sig.signer()));
        List<Object> checks = new ArrayList<>();
        for (Check c : sig.checks()) {
            checks.add(check(c));
        }
        out.put("checks", checks);
        return out;
    }

    private static Map<String, Object> signer(Certificate c) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("common_name", c.commonName());
        out.put("iin", c.iin());
        out.put("bin", c.bin());
        out.put("organization", c.organization());
        out.put("serial_number", c.serialNumber());
        out.put("issuer", c.issuer());
        out.put("key_algorithm", c.keyAlgorithm() != null ? c.keyAlgorithm().jsonValue() : null);
        out.put("policy_oids", new ArrayList<Object>(c.policyOids()));
        out.put("subject_roles", new ArrayList<Object>(c.subjectRoles()));
        out.put("not_before", iso(c.notBefore()));
        out.put("not_after", iso(c.notAfter()));
        return out;
    }

    private static Map<String, Object> check(Check c) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("stage", c.stage().jsonValue());
        out.put("status", c.status().jsonValue());
        if (c.online()) {
            out.put("online", true);
        }
        if ((c.stage() == Stage.TIMESTAMP || c.stage() == Stage.ARCHIVE_TIMESTAMP) && c.time() != null) {
            out.put("time", iso(c.time()));
        }
        if (c.stage() == Stage.REVOCATION && c.revokedAt() != null) {
            out.put("revoked_at", iso(c.revokedAt()));
        }
        if (c.stage() == Stage.REVOCATION && c.revokedReason() != null) {
            out.put("revoked_reason", c.revokedReason());
        }
        if (c.stage() == Stage.REVOCATION && c.validFrom() != null) {
            out.put("valid_from", iso(c.validFrom()));
        }
        if (c.source() != null) {
            out.put("source", c.source().jsonValue());
        }
        if (c.crlUrl() != null) {
            out.put("crl_url", c.crlUrl());
        }
        if (c.detail() != null) {
            out.put("detail", c.detail());
        }
        return out;
    }

    private static String iso(Instant value) {
        if (value == null) {
            return null;
        }
        return value.truncatedTo(ChronoUnit.SECONDS).toString();
    }
}
