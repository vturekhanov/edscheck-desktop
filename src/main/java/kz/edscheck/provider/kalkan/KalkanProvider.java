package kz.edscheck.provider.kalkan;

import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CRLReason;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Locale;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.ASN1TaggedObject;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.ocsp.BasicOCSPResponse;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.RevokedStatus;
import kz.gov.pki.kalkan.ocsp.SingleResp;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.RevocationSource;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.errors.ProviderException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.ArchiveTs;
import kz.edscheck.parsing.ParsedContainer;
import kz.edscheck.parsing.ParsedSigner;
import kz.edscheck.parsing.Parsing;
import kz.edscheck.provider.CommonSigners;
import kz.edscheck.provider.ProviderResult;
import kz.edscheck.provider.SignerVerification;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.TimestampInfo;
import kz.edscheck.provider.VerificationProvider;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.Authorities;
import kz.edscheck.trust.DigestAlgorithms;
import kz.edscheck.trust.KalkanProviderRegistrar;
import kz.edscheck.trust.ManifestTrust;

public final class KalkanProvider implements VerificationProvider {
    private static final String PROV = "KALKAN";
    private static final Set<Stage> CAPABILITIES = Set.of(
        Stage.INTEGRITY, Stage.TIMESTAMP, Stage.CHAIN, Stage.REVOCATION, Stage.ARCHIVE_TIMESTAMP);

    private static final DERObjectIdentifier OID_SIGTST =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.14");
    private static final DERObjectIdentifier OID_REVVALUES =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.24");
    private static final String OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    static {
        KalkanProviderRegistrar.ensureSecurityProviderRegistered();
    }

    private final Trace trace;

    public KalkanProvider() {
        this(Trace.NONE);
    }

    public KalkanProvider(Trace trace) {
        this.trace = trace;
    }

    @Override
    public String name() {
        return "kalkan-java";
    }

    @Override
    public Set<Stage> capabilities() {
        return CAPABILITIES;
    }

    @Override
    public boolean supportsDetached() {
        return true;
    }

    @Override
    public ProviderResult verify(VerificationRequest request, byte[] container) {
        return verifyOne(request, container, null);
    }

    @Override
    public List<ProviderResult> verifyDdcard(
            VerificationRequest request, DocumentSource document, List<byte[]> signatures) {
        List<ProviderResult> out = new ArrayList<>();
        for (byte[] sig : signatures) {
            out.add(verifyOne(request, sig, document));
        }
        return out;
    }

    @Override
    public ProviderResult verifyStreaming(VerificationRequest request, DocumentSource container) {
        List<X509Certificate> trust = ManifestTrust.loadCertificates(request.trust().roots());
        ParsedContainer parsed = Parsing.parseAttached(container, trust);
        return processParsed(request, trust, parsed);
    }

    private ProviderResult verifyOne(VerificationRequest request, byte[] container, DocumentSource document) {

        List<X509Certificate> trust = ManifestTrust.loadCertificates(request.trust().roots());
        ParsedContainer parsed = Parsing.parseContainer(container, trust, document);
        return processParsed(request, trust, parsed);
    }

    private ProviderResult processParsed(
            VerificationRequest request, List<X509Certificate> trust, ParsedContainer parsed) {

        if (parsed.signers().stream().anyMatch(ParsedSigner::isForeign)) {
            List<SignerVerification> foreignSigners = new ArrayList<>();
            for (ParsedSigner ps : parsed.signers()) {
                foreignSigners.add(CommonSigners.foreignSigner(ps));
            }
            return new ProviderResult(parsed.encoding(), foreignSigners);
        }

        boolean ignoreTruststore = request.ignoreTruststore();
        List<X509Certificate> containerCerts = parsed.containerCerts();
        String crlPath = request.trust().crls().isEmpty() ? null : request.trust().crls().get(0);

        Map<Integer, AnchorInfo> anchors = new HashMap<>();
        Map<Integer, String> signerUc = new HashMap<>();
        for (ParsedSigner ps : parsed.signers()) {
            if (ps.signerCertRaw() == null) {
                continue; 
            }
            AnchorInfo anchor = resolveAnchor(ps.signerCertRaw(), containerCerts, trust, ignoreTruststore);
            anchors.put(ps.index(), anchor);
            String anchorTrace;
            if (anchor.anchored()) {
                anchorTrace = anchor.caCert() != null
                    ? Messages.get(MsgKey.PROVIDER_TRACE_ANCHOR_BOUND_WITH_CA,
                        anchor.caCert().getSubjectX500Principal().getName())
                    : Messages.get(MsgKey.PROVIDER_TRACE_ANCHOR_BOUND);
            } else {
                anchorTrace = Messages.get(MsgKey.PROVIDER_TRACE_ANCHOR_NOT_BOUND, anchor.detail());
            }
            trace.v(label(ps) + ": " + anchorTrace);

            String uc;
            if (anchor.caCert() != null) {
                uc = Authorities.detect(anchor.caCert());
            } else if (ignoreTruststore) {
                uc = Authorities.detectPrincipal(anchor.signerIssuerName());
            } else {
                uc = null;
            }
            signerUc.put(ps.index(), uc);
        }

        String target = request.ca();
        boolean allResolved = parsed.signers().stream().allMatch(ps -> ps.signerCertRaw() != null);
        boolean anyAcceptable = signerUc.values().stream()
            .anyMatch(uc -> uc != null && ("auto".equals(target) || uc.equals(target)));
        if (!parsed.signers().isEmpty() && allResolved && !anyAcceptable) {
            String issuers = parsed.signers().stream()
                .map(ps -> ps.certificate().issuer())
                .filter(Objects::nonNull)
                .distinct()
                .sorted()
                .collect(Collectors.joining("; "));
            if (issuers.isEmpty()) {
                issuers = Messages.get(MsgKey.PROVIDER_ISSUERS_UNKNOWN);
            }
            String why = "auto".equals(target)
                ? Messages.get(MsgKey.PROVIDER_SIGNER_CERT_REASON_UNKNOWN_CA)
                : Messages.get(MsgKey.PROVIDER_SIGNER_CERT_REASON_WRONG_CA, Authorities.display(target));
            throw new ProviderException(
                Messages.get(MsgKey.PROVIDER_SIGNER_CERT_REJECTED, why, issuers));
        }

        Set<String> ucs = signerUc.values().stream().filter(Objects::nonNull).collect(Collectors.toSet());
        String containerUc = ucs.size() == 1 ? ucs.iterator().next() : null;

        List<SignerVerification> signers = new ArrayList<>();
        for (ParsedSigner ps : parsed.signers()) {
            if (ps.signerCertRaw() == null) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_UNRESOLVED_SIGNER));
                signers.add(CommonSigners.unresolvedSigner(ps));
                continue;
            }
            Instant refTime = ps.hasTimestamp() && ps.tstGenTime() != null
                ? ps.tstGenTime() : Instant.now();

            TimestampInfo timestamp = ps.hasTimestamp()
                ? timestampInfo(ps, containerCerts, trust, refTime, ignoreTruststore)
                : TimestampInfo.absent();

            StageOutcome revocation = revocationOutcome(
                ps, ps.signerCertRaw(), containerCerts, trust, refTime, crlPath, ignoreTruststore);

            StageOutcome integrity = integrityOutcome(ps, ps.signerCertRaw());

            StageOutcome archive = ps.archiveMarks().isEmpty()
                ? null
                : archiveOutcome(ps, containerCerts, trust, ignoreTruststore);
            AnchorInfo anchor = anchors.get(ps.index());
            String uc = signerUc.get(ps.index());
            if (!anchor.anchored()) {
                signers.add(notAnchoredSigner(ps, timestamp, revocation, integrity, archive, uc));
                continue;
            }
            signers.add(signerAnchored(
                ps, ps.signerCertRaw(), containerCerts, trust, refTime, ignoreTruststore, crlPath,
                timestamp, revocation, integrity, archive, uc));
        }

        return new ProviderResult(parsed.encoding(), signers, containerUc);
    }

    private SignerVerification notAnchoredSigner(
            ParsedSigner ps, TimestampInfo timestamp, StageOutcome revocation, StageOutcome integrity,
            StageOutcome archive, String authority) {
        Map<Stage, StageOutcome> outcomes = new EnumMap<>(Stage.class);
        outcomes.put(Stage.INTEGRITY, integrity);
        outcomes.put(Stage.CHAIN,
            new StageOutcome(CheckStatus.FAIL, Messages.get(MsgKey.PROVIDER_CHAIN_NOT_ANCHORED)));
        outcomes.put(Stage.REVOCATION, revocation);
        if (archive != null) {
            outcomes.put(Stage.ARCHIVE_TIMESTAMP, archive);
        }

        traceMissingBbAttrs(ps);
        return new SignerVerification(ps.index(), ps.certificate(), ps.keyUsage(), timestamp,
            ps.archive(), outcomes, ps.chain(), List.of(), ps.missingBbAttrs(), authority);
    }

    private SignerVerification signerAnchored(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore, String crlPath,
            TimestampInfo timestamp, StageOutcome revocation, StageOutcome integrity, StageOutcome archive,
            String authority) {
        Map<Stage, StageOutcome> outcomes = new EnumMap<>(Stage.class);

        outcomes.put(Stage.INTEGRITY, integrity);

        outcomes.put(Stage.CHAIN, chainOutcome(ps, signerCert, containerCerts, trust, refTime, ignoreTruststore));

        outcomes.put(Stage.REVOCATION, revocation);

        if (archive != null) {
            outcomes.put(Stage.ARCHIVE_TIMESTAMP, archive);
        }

        traceMissingBbAttrs(ps);
        return new SignerVerification(ps.index(), ps.certificate(), ps.keyUsage(), timestamp,
            ps.archive(), outcomes, ps.chain(), List.of(), ps.missingBbAttrs(), authority);
    }

    private void traceMissingBbAttrs(ParsedSigner ps) {
        if (ps.missingBbAttrs().isEmpty()) {
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_BB_ATTRS_OK));
            return;
        }
        trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_BB_ATTRS_MISSING,
            String.join(", ", ps.missingBbAttrs())));
    }

    private StageOutcome integrityOutcome(ParsedSigner ps, X509Certificate signerCert) {
        try {
            boolean ok = ps.signerInfo().verify(signerCert.getPublicKey(), PROV);
            trace.v(label(ps) + ": " + (ok
                ? Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_OK)
                : Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_MISMATCH)));
            return ok ? new StageOutcome(CheckStatus.PASS)
                      : new StageOutcome(CheckStatus.FAIL, Messages.get(MsgKey.PROVIDER_INTEGRITY_MISMATCH));
        } catch (Exception e) {

            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_ERROR,
                e.getClass().getSimpleName() + ": " + e.getMessage()));
            return new StageOutcome(CheckStatus.FAIL, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private StageOutcome chainOutcome(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore) {
        String essAlg = ps.signingCertHashAlg();
        byte[] essHash = ps.signingCertHash();
        if (essAlg != null && essHash != null) {
            String mdName = DigestAlgorithms.jceName(essAlg);
            if (mdName == null) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_UNKNOWN_ALG, essAlg));
                return new StageOutcome(CheckStatus.FAIL,
                    Messages.get(MsgKey.PROVIDER_ESS_UNKNOWN_ALG, essAlg));
            }
            try {
                MessageDigest md = MessageDigest.getInstance(mdName, PROV);
                byte[] calc = md.digest(signerCert.getEncoded());
                if (!Arrays.equals(calc, essHash)) {
                    trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_HASH_MISMATCH, mdName));
                    return new StageOutcome(CheckStatus.FAIL,
                        Messages.get(MsgKey.PROVIDER_ESS_HASH_MISMATCH));
                }
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_HASH_MATCH, mdName));
            } catch (Exception e) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_ERROR, rootMessage(e)));
                return new StageOutcome(CheckStatus.FAIL,
                    Messages.get(MsgKey.PROVIDER_ESS_CHECK_ERROR, rootMessage(e)));
            }
        }
        try {
            buildPath(signerCert, containerCerts, trust, refTime, ignoreTruststore);
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_BUILT));
            return new StageOutcome(CheckStatus.PASS);
        } catch (Exception e) {
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_NOT_BUILT, rootMessage(e)));
            return new StageOutcome(CheckStatus.FAIL, rootMessage(e));
        }
    }

    private TimestampInfo timestampInfo(
            ParsedSigner ps, List<X509Certificate> containerCerts, List<X509Certificate> trust,
            Instant refTime, boolean ignoreTruststore) {
        Boolean sigOk = null;
        Boolean bindingOk = null;
        Boolean chainOk = null;
        Boolean tsaOcspOk = null;
        String tsaOcspDetail = null;
        StageOutcome tsaOcspOutcome = null;
        String detail = null;

        try {
            AttributeTable ut = ps.signerInfo().getUnsignedAttributes();
            Attribute tstAttr = ut == null ? null : ut.get(OID_SIGTST);
            if (tstAttr == null) {
                throw new IllegalStateException(Messages.get(MsgKey.PROVIDER_TIMESTAMP_NO_TST_ATTR));
            }
            ContentInfo ci = ContentInfo.getInstance(tstAttr.getAttrValues().getObjectAt(0));
            CMSSignedData tstCms = new CMSSignedData(ci);
            SignerInformation tstSi =
                (SignerInformation) tstCms.getSignerInfos().getSigners().iterator().next();
            X509Certificate tsaCert = ps.tsaCertRaw();

            try {
                sigOk = tstSi.verify(tsaCert.getPublicKey(), PROV);
            } catch (Exception e) {
                sigOk = false;
            }
            trace.v(label(ps) + ": " + (Boolean.TRUE.equals(sigOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TST_SIGNATURE_OK, tsaCert.getSubjectX500Principal().getName())
                : Messages.get(MsgKey.PROVIDER_TRACE_TST_SIGNATURE_FAIL, tsaCert.getSubjectX500Principal().getName())));

            String mdName = ps.tstImprintAlg() == null ? null : DigestAlgorithms.jceName(ps.tstImprintAlg());
            if (mdName == null) {
                bindingOk = false;
            } else {
                MessageDigest md = MessageDigest.getInstance(mdName, PROV);
                byte[] calc = md.digest(ps.signatureValue());
                bindingOk = Arrays.equals(calc, ps.tstImprintHash());
            }
            trace.v(label(ps) + ": " + (Boolean.TRUE.equals(bindingOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TST_BINDING_OK, mdName)
                : Messages.get(MsgKey.PROVIDER_TRACE_TST_BINDING_FAIL, mdName)));

            String chainDetail = null;
            try {
                buildPath(tsaCert, merge(containerCerts, ps.tsaCertsRaw()), trust, refTime, ignoreTruststore);
                chainOk = true;
            } catch (Exception e) {
                chainOk = false;
                chainDetail = rootMessage(e);
            }
            trace.v(label(ps) + ": " + (Boolean.TRUE.equals(chainOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TSA_CHAIN_OK)
                : Messages.get(MsgKey.PROVIDER_TRACE_TSA_CHAIN_FAIL, chainDetail)));

            AttributeTable tstUt = tstSi.getUnsignedAttributes();
            Attribute revAttr = tstUt == null ? null : tstUt.get(OID_REVVALUES);
            if (revAttr != null) {
                tsaOcspOutcome = revocationOcspOutcome(
                    revAttr, tsaCert, trust, merge(containerCerts, ps.tsaCertsRaw()), refTime, ignoreTruststore,
                    label(ps) + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX));
                tsaOcspOk = tsaOcspOutcome.status() == CheckStatus.PASS;
                tsaOcspDetail = tsaOcspOutcome.detail();
            }

            if (!Boolean.TRUE.equals(sigOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_SIG_FAILED);
            } else if (!Boolean.TRUE.equals(chainOk)) {
                detail = chainDetail;
            } else if (Boolean.FALSE.equals(bindingOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_BINDING_FAILED);
            }
        } catch (Exception e) {
            sigOk = false;
            detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_PARSE_FAILED, e.getMessage());
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_TST_PARSE_FAILED, detail));
        }

        Boolean validityOk = tsaCertInValidity(ps);
        if (validityOk != null) {
            trace.v(label(ps) + ": " + (validityOk
                ? Messages.get(MsgKey.PROVIDER_TRACE_TSA_VALIDITY_OK, traceDt(ps.tstGenTime()))
                : Messages.get(MsgKey.PROVIDER_TRACE_TSA_VALIDITY_FAIL, traceDt(ps.tstGenTime()))));
        }
        if (detail == null && Boolean.FALSE.equals(validityOk)) {
            detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_CERT_EXPIRED);
        }
        if (detail == null && Boolean.FALSE.equals(tsaOcspOk)) {

            detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_TSA_OCSP_PREFIX, tsaOcspDetail);
        }

        boolean valid = !Boolean.FALSE.equals(sigOk) && !Boolean.FALSE.equals(bindingOk)
            && !Boolean.FALSE.equals(chainOk) && !Boolean.FALSE.equals(validityOk)
            && !Boolean.FALSE.equals(tsaOcspOk);

        return new TimestampInfo(true, valid, ps.tstGenTime(), detail, ps.tsaTimestampingEkuOk(), tsaOcspOutcome);
    }

    private static Boolean tsaCertInValidity(ParsedSigner ps) {
        if (ps.tsaCertRaw() == null || ps.tstGenTime() == null) {
            return null;
        }
        Instant notBefore = ps.tsaCertRaw().getNotBefore().toInstant();
        Instant notAfter = ps.tsaCertRaw().getNotAfter().toInstant();
        Instant ref = ps.tstGenTime();
        return !ref.isBefore(notBefore) && !ref.isAfter(notAfter);
    }

    private StageOutcome revocationOutcome(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, String crlPath, boolean ignoreTruststore) {
        AttributeTable ut = ps.signerInfo().getUnsignedAttributes();
        Attribute revAttr = ut == null ? null : ut.get(OID_REVVALUES);
        if (revAttr == null) {
            if (crlPath == null) {
                String noOcspNoCrl = Messages.get(MsgKey.PROVIDER_REVOCATION_NO_OCSP_NO_CRL);
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_REVOCATION_PREFIX, noOcspNoCrl));
                return new StageOutcome(CheckStatus.NOT_VERIFIED, noOcspNoCrl);
            }
            return revocationByCrl(ps, signerCert, trust, containerCerts, crlPath);
        }
        return revocationOcspOutcome(
            revAttr, signerCert, trust, containerCerts, refTime, ignoreTruststore, label(ps));
    }

    private StageOutcome revocationOcspOutcome(
            Attribute revValues, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore, String label) {
        try {
            BasicOCSPResp basic = extractBasicOcsp(revValues);
            if (basic == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_NOT_EXTRACTED));
                return new StageOutcome(CheckStatus.NOT_VERIFIED,
                    Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_NOT_EXTRACTED));
            }
            X509Certificate[] respCerts = basic.getCerts(PROV);
            X509Certificate responder = (respCerts != null && respCerts.length > 0) ? respCerts[0] : null;
            if (responder == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_MISSING));
                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_RESPONDER_MISSING));
            }
            if (!basic.verify(responder.getPublicKey(), PROV)) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_SIGNATURE_FAILED));
                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_SIGNATURE_FAILED));
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_SIGNATURE_OK));
            if (!responder.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal())
                    || !hasOcspSigning(responder)) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_UNAUTHORIZED));
                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_RESPONDER_UNAUTHORIZED));
            }
            List<X509Certificate> respPool = new ArrayList<>(containerCerts);
            respPool.addAll(Arrays.asList(respCerts));
            try {
                buildPath(responder, respPool, trust, refTime, ignoreTruststore);
            } catch (Exception e) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_CHAIN_FAILED,
                    rootMessage(e)));

                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_CHAIN_PREFIX, rootMessage(e)));
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_AUTHORIZED,
                responder.getSubjectX500Principal().getName()));

            X509Certificate issuerCert =
                findBySubject(signerCert.getIssuerX500Principal(), trust, containerCerts);
            if (issuerCert == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_ISSUER_NOT_FOUND));
                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_ISSUER_NOT_FOUND));
            }
            SingleResp match = null;
            for (SingleResp sr : basic.getResponses()) {
                CertificateID respId = sr.getCertID();
                try {
                    CertificateID expectedId = new CertificateID(
                        respId.getHashAlgOID(), issuerCert, signerCert.getSerialNumber(), PROV);
                    if (expectedId.equals(respId)) {
                        match = sr;
                        break;
                    }
                } catch (Exception ignored) {

                }
            }
            if (match == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_CERTID_MISMATCH));
                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_CERTID_MISMATCH));
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_CERTID_MATCH));

            Object status = match.getCertStatus();
            Instant thisUpdate = toInstant(match.getThisUpdate());
            Instant nextUpdate = toInstant(match.getNextUpdate());
            if (status == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_GOOD,
                    traceDt(thisUpdate), traceDt(nextUpdate)));
                return StageOutcome.of(CheckStatus.PASS).source(RevocationSource.OCSP)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_GOOD))
                    .validFrom(thisUpdate).validUntil(nextUpdate).build();
            }
            if (status instanceof RevokedStatus rs) {
                Instant revokedAt = toInstant(rs.getRevocationTime());
                String reason = rs.hasRevocationReason() ? reasonLabel(rs.getRevocationReason()) : null;
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_REVOKED,
                    traceDt(revokedAt), reason));
                return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.OCSP)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_REVOKED))
                    .validFrom(thisUpdate).validUntil(nextUpdate)
                    .revokedAt(revokedAt).revokedReason(reason).build();
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_UNKNOWN));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_STATUS_UNKNOWN));
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
        }
    }

    private static StageOutcome revFail(String detail) {
        return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.OCSP).detail(detail).build();
    }

    StageOutcome revocationByCrl(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, String crlPath) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", PROV);
            X509CRL crl;
            try (InputStream in = new FileInputStream(crlPath)) {
                crl = (X509CRL) cf.generateCRL(in);
            }
            if (!crl.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal())) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_MISMATCH, crlPath));
                return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_FILE)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_MISMATCH)).build();
            }
            X509Certificate issuer = findBySubject(crl.getIssuerX500Principal(), trust, containerCerts);
            if (issuer == null) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_NOT_FOUND, crlPath));
                return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_FILE)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_NOT_FOUND)).build();
            }
            try {
                crl.verify(issuer.getPublicKey(), PROV);
            } catch (Exception e) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_SIGNATURE_FAILED,
                    crlPath, rootMessage(e)));
                return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_FILE)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_SIGNATURE_FAILED, rootMessage(e))).build();
            }
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_SIGNATURE_OK, crlPath));
            Instant thisUpdate = toInstant(crl.getThisUpdate());
            Instant nextUpdate = toInstant(crl.getNextUpdate());
            X509CRLEntry entry = crl.getRevokedCertificate(signerCert);
            if (entry != null) {
                CRLReason r = entry.getRevocationReason();
                String reason = r != null ? reasonLabel(r.ordinal()) : null;
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_REVOKED, reason));
                return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_FILE)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_REVOKED))
                    .validFrom(thisUpdate).validUntil(nextUpdate)
                    .revokedAt(toInstant(entry.getRevocationDate())).revokedReason(reason).build();
            }
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_NOT_REVOKED,
                traceDt(thisUpdate), traceDt(nextUpdate)));
            return StageOutcome.of(CheckStatus.PASS).source(RevocationSource.CRL_FILE)
                .validFrom(thisUpdate).validUntil(nextUpdate).build();
        } catch (Exception e) {
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_PARSE_FAILED, crlPath, rootMessage(e)));
            return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_FILE)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_PARSE_FAILED, rootMessage(e))).build();
        }
    }

    private static BasicOCSPResp extractBasicOcsp(Attribute revValues) throws Exception {

        ASN1Sequence rv = ASN1Sequence.getInstance(revValues.getAttrValues().getObjectAt(0));
        for (int i = 0; i < rv.size(); i++) {
            DEREncodable e = rv.getObjectAt(i);
            if (e instanceof ASN1TaggedObject t) {
                if (t.getTagNo() == 1) {
                    ASN1Sequence ocspVals = ASN1Sequence.getInstance(t, true);
                    BasicOCSPResponse resp = BasicOCSPResponse.getInstance(ocspVals.getObjectAt(0));
                    return new BasicOCSPResp(resp);
                }
            }
        }
        return null;
    }

    private StageOutcome archiveOutcome(
            ParsedSigner ps, List<X509Certificate> containerCerts, List<X509Certificate> trust,
            boolean ignoreTruststore) {
        List<ArchiveTs.Failure> failures = new ArrayList<>();
        for (ArchiveTs.ParsedArchiveTimestamp mark : ps.archiveMarks()) {
            String hashFailure = null;
            Boolean sigOk = null;
            Boolean chainOk = null;
            if (mark.parseError == null) {
                try {
                    var asn1 = new ASN1InputStream(mark.tstDer).readObject();
                    ContentInfo ci = ContentInfo.getInstance(asn1);
                    CMSSignedData tstCms = new CMSSignedData(ci);
                    SignerInformation tstSi =
                        (SignerInformation) tstCms.getSignerInfos().getSigners().iterator().next();
                    try {
                        sigOk = tstSi.verify(mark.tsaCert.getPublicKey(), PROV);
                    } catch (Exception e) {
                        sigOk = false;
                    }
                    try {
                        buildPath(mark.tsaCert, merge(containerCerts, mark.tsaCerts), trust,
                            mark.genTime, ignoreTruststore);
                        chainOk = true;
                    } catch (Exception e) {
                        chainOk = false;
                    }
                } catch (Exception e) {
                    sigOk = false;
                    chainOk = false;
                }

                List<byte[]> certHashes = digestGroup(mark.certBlobs, mark.hashIndAlgOid);
                List<byte[]> crlHashes = digestGroup(mark.crlBlobs, mark.hashIndAlgOid);
                List<byte[]> attrHashes = digestGroup(mark.attrBlobs, mark.hashIndAlgOid);
                byte[] imprint = digestOne(mark.imprintBlob, mark.imprintAlgOid);
                hashFailure = ArchiveTs.evaluateHashes(mark, certHashes, crlHashes, attrHashes, imprint);
            }

            String failure = ArchiveTs.markFailure(
                mark, sigOk, chainOk, chainOk, ArchiveTs.markTsaCertInValidity(mark), hashFailure);
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ARCHIVE_MARK,
                mark.position, failure == null ? Messages.get(MsgKey.PROVIDER_TRACE_ARCHIVE_MARK_OK) : failure));
            if (failure != null) {
                failures.add(new ArchiveTs.Failure(mark.position, failure));
            }
        }
        ArchiveTs.Combined combined = ArchiveTs.combineResults(ps.archiveMarks().size(), failures);
        return new StageOutcome(combined.ok() ? CheckStatus.PASS : CheckStatus.FAIL, combined.detail());
    }

    private static List<byte[]> digestGroup(List<byte[]> blobs, String algOid) {
        String mdName = algOid == null ? null : DigestAlgorithms.jceName(algOid);
        if (mdName == null) {
            return List.of();
        }
        try {
            List<byte[]> out = new ArrayList<>();
            for (byte[] b : blobs) {
                MessageDigest md = MessageDigest.getInstance(mdName, PROV);
                out.add(md.digest(b));
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static byte[] digestOne(byte[] blob, String algOid) {
        if (blob == null) {
            return null;
        }
        String mdName = algOid == null ? null : DigestAlgorithms.jceName(algOid);
        if (mdName == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance(mdName, PROV);
            return md.digest(blob);
        } catch (Exception e) {
            return null;
        }
    }

    private record AnchorInfo(
            boolean anchored, X509Certificate caCert, String detail, X500Principal signerIssuerName) {
    }

    private static AnchorInfo resolveAnchor(
            X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, boolean ignoreTruststore) {
        Set<String> trustedFps = new HashSet<>();
        Map<X500Principal, X509Certificate> trustedBySubject = new HashMap<>();
        for (X509Certificate c : trust) {
            trustedFps.add(fingerprint(c));
            trustedBySubject.putIfAbsent(c.getSubjectX500Principal(), c);
        }
        Map<X500Principal, X509Certificate> containerBySubject = new HashMap<>();
        for (X509Certificate c : containerCerts) {
            containerBySubject.putIfAbsent(c.getSubjectX500Principal(), c);
        }

        X500Principal signerIssuerName = signerCert.getIssuerX500Principal();

        X509Certificate current = signerCert;
        X509Certificate caCert = null;
        Set<X500Principal> seen = new HashSet<>();
        while (true) {
            if (!ignoreTruststore && trustedFps.contains(fingerprint(current))) {
                return new AnchorInfo(true, caCert, null, signerIssuerName);
            }
            X500Principal issuerDn = current.getIssuerX500Principal();
            if (current.getSubjectX500Principal().equals(issuerDn)) {
                if (trustedFps.contains(fingerprint(current))) {
                    return new AnchorInfo(true, caCert, null, signerIssuerName);
                }
                String detail = ignoreTruststore
                    ? Messages.get(MsgKey.PROVIDER_ANCHOR_SELF_SIGNED_MISMATCH)
                    : Messages.get(MsgKey.PROVIDER_ANCHOR_ROOT_NOT_TRUSTED);
                return new AnchorInfo(false, caCert, detail, signerIssuerName);
            }
            X509Certificate issuer = ignoreTruststore
                ? containerBySubject.get(issuerDn)
                : (trustedBySubject.containsKey(issuerDn)
                    ? trustedBySubject.get(issuerDn) : containerBySubject.get(issuerDn));
            if (issuer == null) {
                String detail = ignoreTruststore
                    ? Messages.get(MsgKey.PROVIDER_ANCHOR_ISSUER_NOT_FOUND_FILE)
                    : Messages.get(MsgKey.PROVIDER_ANCHOR_ISSUER_NOT_FOUND);
                return new AnchorInfo(false, caCert, detail, signerIssuerName);
            }
            if (seen.contains(issuer.getSubjectX500Principal())) {
                return new AnchorInfo(false, caCert, Messages.get(MsgKey.PROVIDER_ANCHOR_CYCLE), signerIssuerName);
            }
            seen.add(issuer.getSubjectX500Principal());
            if (caCert == null) {
                caCert = issuer;
            }
            current = issuer;
        }
    }

    private static String fingerprint(X509Certificate c) {
        try {
            return Base64.getEncoder().encodeToString(c.getEncoded());
        } catch (CertificateEncodingException e) {
            return "";
        }
    }

    private static void buildPath(
            X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore) throws Exception {
        buildPath(target, containerCerts, trust, refTime == null ? null : Date.from(refTime), ignoreTruststore);
    }

    private static void buildPath(
            X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Date refTime, boolean ignoreTruststore) throws Exception {
        Set<TrustAnchor> anchors = new HashSet<>();
        if (ignoreTruststore) {
            for (X509Certificate c : containerCerts) {
                if (c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
                    anchors.add(new TrustAnchor(c, null));
                }
            }
            if (anchors.isEmpty()) {

                throw new Exception(Messages.get(MsgKey.PROVIDER_CHAIN_NOT_ANCHORED));
            }
        } else {
            for (X509Certificate c : trust) {
                anchors.add(new TrustAnchor(c, null));
            }
        }

        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(target);

        PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, sel);
        params.setRevocationEnabled(false); 
        if (refTime != null) {
            params.setDate(refTime); 
        }

        List<java.security.cert.Certificate> pool = new ArrayList<>();
        pool.add(target);
        for (X509Certificate c : containerCerts) {
            if (isCa(c) && !c.equals(target)) {
                pool.add(c);
            }
        }
        if (!ignoreTruststore) {
            for (X509Certificate c : trust) {
                if (!c.equals(target)) {
                    pool.add(c);
                }
            }
        }
        CertStore cs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool), PROV);
        params.addCertStore(cs);

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", PROV);
        CertPathBuilderResult result = builder.build(params); 

        if (ignoreTruststore) {
            X509Certificate rootUsed =
                ((PKIXCertPathBuilderResult) result).getTrustAnchor().getTrustedCert();
            boolean pinned = false;
            for (X509Certificate t : trust) {
                if (Arrays.equals(t.getEncoded(), rootUsed.getEncoded())) {
                    pinned = true;
                    break;
                }
            }
            if (!pinned) {
                throw new Exception(Messages.get(MsgKey.PROVIDER_ANCHOR_SELF_SIGNED_MISMATCH));
            }
        }
    }

    private static boolean isCa(X509Certificate cert) {
        return cert.getBasicConstraints() >= 0;
    }

    private static String label(ParsedSigner ps) {
        return Messages.get(MsgKey.PROVIDER_LABEL_SIGNATURE, ps.index() + 1);
    }

    private static final DateTimeFormatter TRACE_DT_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx", Locale.ROOT);

    private static String traceDt(Instant value) {
        return value == null ? "null" : value.atZone(ZoneId.systemDefault()).format(TRACE_DT_FMT);
    }

    private static List<X509Certificate> merge(List<X509Certificate> a, List<X509Certificate> b) {
        List<X509Certificate> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    private static X509Certificate findBySubject(
            X500Principal subject, List<X509Certificate> a, List<X509Certificate> b) {
        for (X509Certificate c : a) {
            if (c.getSubjectX500Principal().equals(subject)) {
                return c;
            }
        }
        for (X509Certificate c : b) {
            if (c.getSubjectX500Principal().equals(subject)) {
                return c;
            }
        }
        return null;
    }

    private static boolean hasOcspSigning(X509Certificate cert) {
        try {
            List<String> eku = cert.getExtendedKeyUsage();
            return eku != null && eku.contains(OID_OCSP_SIGNING);
        } catch (Exception e) {
            return false;
        }
    }

    private static Instant toInstant(Date d) {
        return d == null ? null : d.toInstant();
    }

    private static String reasonLabel(int code) {
        switch (code) {
            case 0: return "unspecified";
            case 1: return "key_compromise";
            case 2: return "ca_compromise";
            case 3: return "affiliation_changed";
            case 4: return "superseded";
            case 5: return "cessation_of_operation";
            case 6: return "certificate_hold";
            case 8: return "remove_from_crl";
            case 9: return "privilege_withdrawn";
            case 10: return "aa_compromise";
            default: return null;
        }
    }

    private static String rootMessage(Throwable e) {
        Throwable c = e;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        String m = c.getMessage();
        return m == null ? c.getClass().getSimpleName() : m;
    }
}
