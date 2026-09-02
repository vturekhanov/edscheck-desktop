package kz.edscheck.xml;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.Check;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.domain.Signature;
import kz.edscheck.engine.VerificationEngine;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.Parsing;
import kz.edscheck.provider.ArchiveTimestampInfo;
import kz.edscheck.provider.KeyUsageInfo;
import kz.edscheck.provider.SignerVerification;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.TimestampInfo;
import kz.edscheck.rules.PolicyProfile;
import kz.edscheck.rules.Rules;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.ManifestTrust;

final class EsfSignatureAssembler {
    private EsfSignatureAssembler() {
    }

    static Signature assemble(EsfInvoice invoice, VerificationRequest request, Trace trace) {
        List<X509Certificate> trust = ManifestTrust.loadCertificates(request.trust().roots());
        boolean ignoreTruststore = request.ignoreTruststore();
        String crlPath = request.trust().crls().isEmpty() ? null : request.trust().crls().get(0);
        Map<String, byte[]> externalOcsp = request.externalOcsp();
        PolicyProfile policy = PolicyProfile.ncaPolicy();
        X509Certificate signerCert = invoice.certificateRaw();
        Instant refTime = Instant.now(); 

        String label = Messages.get(MsgKey.PROVIDER_LABEL_SIGNATURE, 1);

        String authority;
        if (signerCert == null) {
            trace.v(label + ": " + Messages.get(MsgKey.XML_NO_CERTIFICATE));
            authority = null;
        } else {
            authority = XmlCrypto.traceAndResolveAuthority(
                signerCert, List.of(signerCert), trust, ignoreTruststore, trace, label);
        }

        Map<Stage, StageOutcome> outcomes = new EnumMap<>(Stage.class);

        XmlIntegrityResult integrity = XmlCrypto.verifyEsfIntegrity(invoice, trace, label);
        outcomes.put(Stage.INTEGRITY, integrity.outcome() == IntegrityOutcome.VALID
            ? new StageOutcome(CheckStatus.PASS)
            : new StageOutcome(CheckStatus.FAIL, integrity.errorDetail()));

        XmlChainResult chainResult = signerCert == null
            ? new XmlChainResult(
                new StageOutcome(CheckStatus.NOT_VERIFIED, Messages.get(MsgKey.XML_NO_CERTIFICATE)), List.of())
            : XmlCrypto.verifyChain(signerCert, List.of(signerCert), trust, refTime, ignoreTruststore, List.of(),
                List.of(), List.of(), crlPath, externalOcsp, trace, label);
        outcomes.put(Stage.CHAIN, chainResult.outcome());

        outcomes.put(Stage.REVOCATION, signerCert == null
            ? new StageOutcome(CheckStatus.NOT_VERIFIED, Messages.get(MsgKey.XML_NO_CERTIFICATE))
            : new kz.edscheck.provider.kalkan.KalkanProvider(trace).revocationCascadeForBag(
                signerCert, List.of(), List.of(), List.of(signerCert), trust, refTime, crlPath,
                ignoreTruststore, externalOcsp, label));

        KeyUsageInfo keyUsage = signerCert == null ? new KeyUsageInfo() : Parsing.keyUsageInfo(signerCert);
        List<Certificate> chain = signerCert == null ? List.of()
            : Parsing.resolveChain(signerCert, bySubject(trust, signerCert));

        Rules.CheckAndWarnings signedAttrsResult = new Rules.CheckAndWarnings(
            new Check(Stage.SIGNED_ATTRIBUTES, CheckStatus.WARN,
                Messages.get(MsgKey.XML_ESF_SIGNED_ATTRS_WARN)),
            List.of());

        SignerVerification sv = new SignerVerification(
            0, invoice.certificate(), keyUsage, TimestampInfo.absent(), ArchiveTimestampInfo.none(),
            outcomes, chain, List.of(), List.of(), authority, chainResult.intermediateCaRevocations());

        return VerificationEngine.assembleSignature(sv, Set.of(), policy, signedAttrsResult);
    }

    private static Map<X500Principal, X509Certificate> bySubject(List<X509Certificate> trust, X509Certificate signerCert) {
        Map<X500Principal, X509Certificate> bySubject = new HashMap<>();
        for (X509Certificate c : trust) {
            bySubject.putIfAbsent(c.getSubjectX500Principal(), c);
        }
        bySubject.putIfAbsent(signerCert.getSubjectX500Principal(), signerCert);
        return bySubject;
    }
}
