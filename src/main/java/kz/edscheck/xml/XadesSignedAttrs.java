package kz.edscheck.xml;

import java.util.ArrayList;
import java.util.List;

import kz.edscheck.domain.Check;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.Stage;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.rules.PolicyProfile;
import kz.edscheck.rules.Rules;
import kz.edscheck.trace.Trace;

final class XadesSignedAttrs {
    private XadesSignedAttrs() {
    }

    static Rules.CheckAndWarnings check(ParsedXmlSignature ps, PolicyProfile policy, Trace trace) {
        if (!ps.qualifyingPropertiesPresent()) {
            return new Rules.CheckAndWarnings(
                new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.SKIP,
                    Messages.get(MsgKey.XML_SIGNED_PROPERTIES_NOT_APPLICABLE)),
                List.of());
        }
        if (!ps.signedPropertiesPresent()) {
            return new Rules.CheckAndWarnings(
                new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.NOT_VERIFIED,
                    Messages.get(MsgKey.XML_SIGNED_PROPERTIES_ABSENT)),
                List.of());
        }

        List<String> missing = new ArrayList<>();
        if (ps.signingTime() == null) {
            missing.add("SigningTime");
        }
        if (ps.signingCertificateV2().isEmpty()) {
            missing.add("SigningCertificateV2");
        }
        missing.addAll(ps.forbiddenV1Forms());

        if (missing.isEmpty()) {
            trace.v(label(ps) + ": " + Messages.get(MsgKey.XML_TRACE_SIGNED_PROPERTIES_PRESENT));
            return new Rules.CheckAndWarnings(
                new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.PASS), List.of());
        }
        String joined = String.join(", ", missing);
        trace.v(label(ps) + ": " + Messages.get(MsgKey.XML_TRACE_SIGNED_PROPERTIES_MISSING, joined));
        if (policy.requireBbAttrs()) {
            return new Rules.CheckAndWarnings(
                new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.FAIL,
                    Messages.get(MsgKey.XML_SIGNED_PROPERTIES_MISSING_REQUIRED, joined)),
                List.of());
        }
        return new Rules.CheckAndWarnings(
            new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.WARN,
                Messages.get(MsgKey.XML_SIGNED_PROPERTIES_MISSING_REQUIRED, joined)),
            List.of());
    }

    private static String label(ParsedXmlSignature ps) {
        return Messages.get(MsgKey.PROVIDER_LABEL_SIGNATURE, ps.index() + 1);
    }
}
