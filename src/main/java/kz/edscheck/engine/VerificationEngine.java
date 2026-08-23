package kz.edscheck.engine;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import kz.edscheck.ddcard.Ddcard;
import kz.edscheck.ddcard.DdcardContent;
import kz.edscheck.domain.Check;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.Encoding;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.Signature;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.ProviderResult;
import kz.edscheck.provider.SignerVerification;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.VerificationProvider;
import kz.edscheck.rules.PolicyProfile;
import kz.edscheck.rules.Rules;
import kz.edscheck.trace.Trace;
import kz.edscheck.xml.XmlDetect;
import kz.edscheck.xml.XmlVerifier;

public final class VerificationEngine {
    private final VerificationProvider provider;
    private final PolicyProfile policy;
    private final Trace trace;
    private final Map<Integer, byte[]> xmlOnlineOcsp;

    public VerificationEngine(VerificationProvider provider) {
        this(provider, PolicyProfile.ncaPolicy(), Trace.NONE, Map.of());
    }

    public VerificationEngine(VerificationProvider provider, PolicyProfile policy) {
        this(provider, policy, Trace.NONE, Map.of());
    }

    public VerificationEngine(VerificationProvider provider, Trace trace) {
        this(provider, PolicyProfile.ncaPolicy(), trace, Map.of());
    }

    public VerificationEngine(VerificationProvider provider, PolicyProfile policy, Trace trace) {
        this(provider, policy, trace, Map.of());
    }

    public VerificationEngine(
            VerificationProvider provider, Trace trace, Map<Integer, byte[]> xmlOnlineOcsp) {
        this(provider, PolicyProfile.ncaPolicy(), trace, xmlOnlineOcsp);
    }

    public VerificationEngine(
            VerificationProvider provider, PolicyProfile policy, Trace trace,
            Map<Integer, byte[]> xmlOnlineOcsp) {
        this.provider = provider;
        this.policy = policy != null ? policy : PolicyProfile.ncaPolicy();
        this.trace = trace != null ? trace : Trace.NONE;
        this.xmlOnlineOcsp = xmlOnlineOcsp != null ? xmlOnlineOcsp : Map.of();
    }

    public SignedContainer verify(VerificationRequest request, byte[] container) {

        if (Ddcard.detectInputFormat(container).equals("ddcard")) {
            return verifyDdcard(request, container);
        }
        if (XmlDetect.looksLikeXml(container)) {
            return XmlVerifier.verify(request, container, null, xmlOnlineOcsp, trace);
        }
        return verifyCms(request, container);
    }

    public SignedContainer verify(VerificationRequest request, DocumentSource container) {
        boolean ddcard;
        try {
            ddcard = Ddcard.looksLikeDdcard(container);
        } catch (IOException e) {
            throw new ContainerException(
                Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
        }
        if (ddcard) {
            byte[] bytes;
            try {
                bytes = container.readAllBytes();
            } catch (IOException e) {
                throw new ContainerException(
                    Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
            }
            return verifyDdcard(request, bytes);
        }
        boolean xml;
        try {
            xml = XmlDetect.looksLikeXml(container);
        } catch (IOException e) {
            throw new ContainerException(
                Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
        }
        if (xml) {

            return XmlVerifier.verify(request, container, xmlOnlineOcsp, trace);
        }
        ProviderResult result = provider.verifyStreaming(request, container);
        return assembleCmsResult(request, result);
    }

    private SignedContainer verifyCms(VerificationRequest request, byte[] container) {
        ProviderResult result = provider.verify(request, container);
        return assembleCmsResult(request, result);
    }

    private SignedContainer assembleCmsResult(VerificationRequest request, ProviderResult result) {
        Set<Stage> capabilities = provider.capabilities();
        List<Signature> signatures = new ArrayList<>();
        for (SignerVerification sv : result.signers()) {
            signatures.add(assembleSignature(sv, capabilities));
        }
        return new SignedContainer(
            request.containerPath(), result.encoding(), result.signaturesTotal(),
            signatures, "cms", null, result.authority());
    }

    private SignedContainer verifyDdcard(VerificationRequest request, byte[] container) {
        DdcardContent content = Ddcard.parseDdcard(container);

        return verifyDetached(request, content.document(), content.signatures(),
            content.documentName(), "ddcard");
    }

    public SignedContainer verifyWithDocument(
            VerificationRequest request, byte[] container, DocumentSource document, String documentName) {
        if (XmlDetect.looksLikeXml(container)) {
            return XmlVerifier.verify(request, container, document, xmlOnlineOcsp, trace);
        }
        return verifyDetached(request, document, List.of(container), documentName);
    }

    public SignedContainer verifyDetached(
            VerificationRequest request, byte[] document, List<byte[]> signatures) {
        return verifyDetached(request, DocumentSource.ofBytes(document), signatures, null, "detached");
    }

    public SignedContainer verifyDetached(
            VerificationRequest request, byte[] document, List<byte[]> signatures,
            String documentName) {
        return verifyDetached(request, DocumentSource.ofBytes(document), signatures, documentName, "detached");
    }

    public SignedContainer verifyDetached(
            VerificationRequest request, DocumentSource document, List<byte[]> signatures,
            String documentName) {
        return verifyDetached(request, document, signatures, documentName, "detached");
    }

    private SignedContainer verifyDetached(
            VerificationRequest request, DocumentSource document, List<byte[]> signatures,
            String documentName, String containerFormat) {
        Set<Stage> capabilities = provider.capabilities();
        boolean detachedNative = provider.supportsDetached();

        List<ProviderResult> results;
        if (detachedNative) {
            results = provider.verifyDdcard(request, document, signatures);
        } else {
            byte[] documentBytes;
            try {
                documentBytes = document.readAllBytes();
            } catch (IOException e) {
                throw new ContainerException(
                    Messages.get(MsgKey.CONTAINER_DOCUMENT_READ_FAILED, e.getMessage()), e);
            }
            results = new ArrayList<>();
            for (byte[] cmsBytes : signatures) {
                results.add(provider.verify(request, Ddcard.reconstructAttached(cmsBytes, documentBytes)));
            }
        }

        List<Signature> assembled = new ArrayList<>();
        Encoding encoding = null;
        String authority = null;
        for (ProviderResult result : results) {
            if (encoding == null) {
                encoding = result.encoding();
            }
            if (authority == null) {
                authority = result.authority();
            }
            for (SignerVerification sv : result.signers()) {
                sv.setIndex(assembled.size()); 
                assembled.add(assembleSignature(sv, capabilities));
            }
        }
        return new SignedContainer(
            request.containerPath(), encoding != null ? encoding : Encoding.DER,
            assembled.size(), assembled, containerFormat, documentName, authority);
    }

    private Signature assembleSignature(SignerVerification sv, Set<Stage> capabilities) {

        Rules.CheckAndWarnings signedAttrsResult = Rules.signedAttrsCheck(sv.missingBbAttrs(), policy);
        return assembleSignature(sv, capabilities, policy, signedAttrsResult);
    }

    public static Signature assembleSignature(
            SignerVerification sv, Set<Stage> capabilities, PolicyProfile policy,
            Rules.CheckAndWarnings signedAttrsResult) {
        kz.edscheck.domain.ReferenceTime referenceTime = Rules.computeReferenceTime(sv.timestamp(), policy);
        Rules.CheckAndWarnings tsResult = Rules.timestampCheck(sv.timestamp(), policy);
        Check tsCheck = tsResult.check();
        Check signedAttrsCheck = signedAttrsResult.check();
        List<String> warnings = new ArrayList<>(tsResult.warnings());
        warnings.addAll(signedAttrsResult.warnings());
        warnings.addAll(sv.warnings()); 

        StageOutcome revocationOutcome = sv.outcomes().get(Stage.REVOCATION);
        Check revocation = cryptoCheck(Stage.REVOCATION, sv, capabilities);
        revocation = Rules.applyRevocationDate(revocation, revocationOutcome).check();

        revocation = Rules.applyRevocationPeriod(
            revocation, revocationOutcome, referenceTime.value(), Instant.now(),
            sv.certificate().notAfter(), policy);

        revocation = Rules.applyOcspSigningWindow(
            revocation, revocationOutcome, referenceTime.value(), policy);

        Rules.CheckAndWarnings archiveResult = Rules.archiveTimestampCheck(
            sv.archive(), sv.outcomes().get(Stage.ARCHIVE_TIMESTAMP));
        Check archiveCheck = archiveResult.check();

        List<Check> checks = List.of(
            cryptoCheck(Stage.INTEGRITY, sv, capabilities),
            signedAttrsCheck,
            tsCheck,
            cryptoCheck(Stage.CHAIN, sv, capabilities),
            Rules.decideKeyUsage(sv.keyUsage(), policy),
            Rules.decideValidity(referenceTime.value(), sv.certificate(), policy, sv.chain()),
            revocation,
            archiveCheck);

        List<String> allWarnings = new ArrayList<>(warnings);
        allWarnings.addAll(archiveResult.warnings());

        return new Signature(sv.index(), Rules.computeVerdict(checks), sv.certificate(),
            referenceTime, checks, allWarnings, sv.authority());
    }

    public static Check cryptoCheck(Stage stage, SignerVerification sv, Set<Stage> capabilities) {
        StageOutcome outcome = sv.outcomes().get(stage);
        if (outcome != null) {
            return Rules.outcomeToCheck(stage, outcome);
        }
        if (!capabilities.contains(stage)) {
            return new Check(stage, CheckStatus.NOT_VERIFIED,
                Messages.get(MsgKey.ENGINE_PROVIDER_STAGE_UNSUPPORTED));
        }
        return new Check(stage, CheckStatus.NOT_VERIFIED, Messages.get(MsgKey.ENGINE_STAGE_NO_RESULT));
    }
}
