package kz.edscheck.xml;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.DocumentSource;
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

final class XmlSignatureAssembler {
    private XmlSignatureAssembler() {
    }

    static List<Signature> assemble(
            Document doc, List<ParsedXmlSignature> signatures, VerificationRequest request,
            DocumentSource externalDocument, Map<Integer, byte[]> onlineOcsp, Trace trace) {
        List<X509Certificate> trust = ManifestTrust.loadCertificates(request.trust().roots());
        boolean ignoreTruststore = request.ignoreTruststore();
        String crlPath = request.trust().crls().isEmpty() ? null : request.trust().crls().get(0);
        NodeList sigElements = doc.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Signature");
        PolicyProfile policy = PolicyProfile.ncaPolicy();

        List<Signature> result = new ArrayList<>(signatures.size());
        for (ParsedXmlSignature ps : signatures) {
            Element sigEl = (Element) sigElements.item(ps.index());
            result.add(assembleOne(doc, sigEl, ps, trust, ignoreTruststore, crlPath, policy, externalDocument, onlineOcsp, trace));
        }
        return result;
    }

    private static Signature assembleOne(
            Document doc, Element sigEl, ParsedXmlSignature ps,
            List<X509Certificate> trust, boolean ignoreTruststore, String crlPath, PolicyProfile policy,
            DocumentSource externalDocument, Map<Integer, byte[]> onlineOcsp, Trace trace) {
        X509Certificate signerCert = ps.certificateRaw();
        List<X509Certificate> containerCerts = signerCert == null ? List.of() : List.of(signerCert);

        Instant provisionalGenTime = peekGenTime(ps.signatureTimestampToken());
        Instant refTime = provisionalGenTime != null ? provisionalGenTime : Instant.now();

        String label = Messages.get(MsgKey.PROVIDER_LABEL_SIGNATURE, ps.index() + 1);

        String authority;
        if (signerCert == null) {
            trace.v(label + ": " + Messages.get(MsgKey.XML_NO_CERTIFICATE));
            authority = null;
        } else {
            authority = XmlCrypto.traceAndResolveAuthority(
                signerCert, containerCerts, trust, ignoreTruststore, trace, label);
        }

        Map<Stage, StageOutcome> outcomes = new EnumMap<>(Stage.class);

        XmlIntegrityResult integrity =
            XmlCrypto.verifyIntegrity(doc, sigEl, signerCert, "", externalDocument, trace, label);
        outcomes.put(Stage.INTEGRITY, toStageOutcome(integrity));

        outcomes.put(Stage.CHAIN, signerCert == null
            ? new StageOutcome(CheckStatus.NOT_VERIFIED, Messages.get(MsgKey.XML_NO_CERTIFICATE))
            : XmlCrypto.verifyChain(signerCert, containerCerts, trust, refTime, ignoreTruststore,
                ps.signingCertificateV2(), trace, label));

        TimestampInfo timestamp = signerCert == null
            ? TimestampInfo.absent()
            : XmlCrypto.verifyTimestamp(ps, sigEl, containerCerts, trust, refTime, ignoreTruststore, trace, label);

        outcomes.put(Stage.REVOCATION, signerCert == null
            ? new StageOutcome(CheckStatus.NOT_VERIFIED, Messages.get(MsgKey.XML_NO_CERTIFICATE))
            : XmlCrypto.verifyEmbeddedOcsp(ocspValuesWithOnline(ps, onlineOcsp), ps.crlValues(), crlPath, signerCert,
                trust, containerCerts, refTime, ignoreTruststore, trace, label));

        KeyUsageInfo keyUsage = signerCert == null ? new KeyUsageInfo() : Parsing.keyUsageInfo(signerCert);

        List<Certificate> chain = signerCert == null ? List.of() : Parsing.resolveChain(signerCert, bySubject(trust, signerCert));

        Rules.CheckAndWarnings signedAttrsResult = XadesSignedAttrs.check(ps, policy, trace);

        SignerVerification sv = new SignerVerification(
            ps.index(), ps.certificate(), keyUsage, timestamp, ArchiveTimestampInfo.none(),
            outcomes, chain, List.of(), List.of(), authority);

        return VerificationEngine.assembleSignature(sv, Set.of(), policy, signedAttrsResult);
    }

    private static List<byte[]> ocspValuesWithOnline(ParsedXmlSignature ps, Map<Integer, byte[]> onlineOcsp) {
        byte[] online = onlineOcsp.get(ps.index());
        if (online == null) {
            return ps.ocspValues();
        }
        List<byte[]> combined = new ArrayList<>(ps.ocspValues());
        combined.add(online);
        return combined;
    }

    private static StageOutcome toStageOutcome(XmlIntegrityResult integrity) {
        return switch (integrity.outcome()) {
            case VALID -> new StageOutcome(CheckStatus.PASS);
            case INVALID -> new StageOutcome(CheckStatus.FAIL, integrity.errorDetail());
            case UNRESOLVABLE -> new StageOutcome(CheckStatus.NOT_VERIFIED,
                Messages.get(MsgKey.XML_DETACHED_NO_DOCUMENT, integrity.errorDetail()));
        };
    }

    private static Instant peekGenTime(byte[] tstDer) {
        if (tstDer == null) {
            return null;
        }
        try {
            kz.gov.pki.kalkan.asn1.ASN1InputStream ain = new kz.gov.pki.kalkan.asn1.ASN1InputStream(tstDer);
            kz.gov.pki.kalkan.asn1.cms.ContentInfo ci =
                kz.gov.pki.kalkan.asn1.cms.ContentInfo.getInstance(ain.readObject());
            kz.gov.pki.kalkan.tsp.TimeStampToken tst = new kz.gov.pki.kalkan.tsp.TimeStampToken(ci);
            var genTime = tst.getTimeStampInfo().getGenTime();
            return genTime == null ? null : genTime.toInstant();
        } catch (Exception e) {
            return null;
        }
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
