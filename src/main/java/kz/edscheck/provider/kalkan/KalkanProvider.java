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
import java.util.HexFormat;
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
import kz.gov.pki.kalkan.ocsp.OCSPResp;
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
import kz.edscheck.provider.ArchiveMarkOutcome;
import kz.edscheck.provider.CaRevocationFact;
import kz.edscheck.provider.CommonSigners;
import kz.edscheck.provider.OnlineRevocationRequest;
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

    private static final int TAG_CRL_VALS = 0;
    private static final int TAG_OCSP_VALS = 1;

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
        boolean ignoreTruststore = request.ignoreTruststore();
        List<X509Certificate> containerCerts = parsed.containerCerts();
        String crlPath = request.trust().crls().isEmpty() ? null : request.trust().crls().get(0);
        Map<String, byte[]> externalOcsp = request.externalOcsp();

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
                ? timestampInfo(ps, containerCerts, trust, refTime, ignoreTruststore, parsed.crlBlobs(), crlPath,
                    externalOcsp)
                : TimestampInfo.absent();

            StageOutcome revocation = revocationOutcome(
                ps, ps.signerCertRaw(), containerCerts, trust, refTime, crlPath, ignoreTruststore,
                parsed.crlBlobs(), externalOcsp);

            StageOutcome integrity = integrityOutcome(ps, ps.signerCertRaw());

            List<ArchiveMarkOutcome> archiveMarkOutcomes = ps.archiveMarks().isEmpty()
                ? List.of()
                : archiveOutcome(ps, containerCerts, trust, ignoreTruststore, parsed.crlBlobs(), crlPath,
                    externalOcsp);
            AnchorInfo anchor = anchors.get(ps.index());
            String uc = signerUc.get(ps.index());
            if (!anchor.anchored()) {
                signers.add(notAnchoredSigner(ps, timestamp, revocation, integrity, archiveMarkOutcomes, uc));
                continue;
            }
            signers.add(signerAnchored(
                ps, ps.signerCertRaw(), containerCerts, trust, refTime, ignoreTruststore, crlPath,
                parsed.crlBlobs(), timestamp, revocation, integrity, archiveMarkOutcomes, uc, externalOcsp));
        }

        return new ProviderResult(parsed.encoding(), signers, containerUc);
    }

    private SignerVerification notAnchoredSigner(
            ParsedSigner ps, TimestampInfo timestamp, StageOutcome revocation, StageOutcome integrity,
            List<ArchiveMarkOutcome> archiveMarkOutcomes, String authority) {
        Map<Stage, StageOutcome> outcomes = new EnumMap<>(Stage.class);
        outcomes.put(Stage.INTEGRITY, integrity);
        outcomes.put(Stage.CHAIN,
            new StageOutcome(CheckStatus.FAIL, Messages.get(MsgKey.PROVIDER_CHAIN_NOT_ANCHORED)));
        outcomes.put(Stage.REVOCATION, revocation);

        traceMissingBbAttrs(ps);
        return new SignerVerification(ps.index(), ps.certificate(), ps.keyUsage(), timestamp,
            ps.archive(), outcomes, ps.chain(), List.of(), ps.missingBbAttrs(), authority,
            List.of(), archiveMarkOutcomes);
    }

    private SignerVerification signerAnchored(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore, String crlPath,
            List<byte[]> rootCrlBlobs, TimestampInfo timestamp, StageOutcome revocation, StageOutcome integrity,
            List<ArchiveMarkOutcome> archiveMarkOutcomes, String authority, Map<String, byte[]> externalOcsp) {
        Map<Stage, StageOutcome> outcomes = new EnumMap<>(Stage.class);

        outcomes.put(Stage.INTEGRITY, integrity);

        ChainResult chainResult = chainOutcome(
            ps, signerCert, containerCerts, trust, refTime, ignoreTruststore, rootCrlBlobs, crlPath, externalOcsp);
        outcomes.put(Stage.CHAIN, chainResult.outcome());

        outcomes.put(Stage.REVOCATION, revocation);

        traceMissingBbAttrs(ps);
        return new SignerVerification(ps.index(), ps.certificate(), ps.keyUsage(), timestamp,
            ps.archive(), outcomes, ps.chain(), List.of(), ps.missingBbAttrs(), authority,
            chainResult.intermediateCaRevocations(), archiveMarkOutcomes);
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

    private record ChainResult(StageOutcome outcome, List<CaRevocationFact> intermediateCaRevocations) {
    }

    private ChainResult chainOutcome(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore,
            List<byte[]> rootCrlBlobs, String crlPath, Map<String, byte[]> externalOcsp) {
        String essAlg = ps.signingCertHashAlg();
        byte[] essHash = ps.signingCertHash();
        if (essAlg != null && essHash != null) {
            String mdName = DigestAlgorithms.jceName(essAlg);
            if (mdName == null) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_UNKNOWN_ALG, essAlg));
                return new ChainResult(new StageOutcome(CheckStatus.FAIL,
                    Messages.get(MsgKey.PROVIDER_ESS_UNKNOWN_ALG, essAlg)), List.of());
            }
            try {
                MessageDigest md = MessageDigest.getInstance(mdName, PROV);
                byte[] calc = md.digest(signerCert.getEncoded());
                if (!Arrays.equals(calc, essHash)) {
                    trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_HASH_MISMATCH, mdName));
                    return new ChainResult(new StageOutcome(CheckStatus.FAIL,
                        Messages.get(MsgKey.PROVIDER_ESS_HASH_MISMATCH)), List.of());
                }
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_HASH_MATCH, mdName));
            } catch (Exception e) {
                trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ESS_ERROR, rootMessage(e)));
                return new ChainResult(new StageOutcome(CheckStatus.FAIL,
                    Messages.get(MsgKey.PROVIDER_ESS_CHECK_ERROR, rootMessage(e))), List.of());
            }
        }
        try {
            List<X509Certificate> path = buildPath(signerCert, containerCerts, trust, refTime, ignoreTruststore);
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_BUILT));
            List<CaRevocationFact> facts = intermediateCaFacts(
                path, rootCrlBlobs, containerCerts, trust, refTime, crlPath, ignoreTruststore, label(ps),
                externalOcsp);
            return new ChainResult(new StageOutcome(CheckStatus.PASS), facts);
        } catch (Exception e) {
            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_NOT_BUILT, rootMessage(e)));
            return new ChainResult(new StageOutcome(CheckStatus.FAIL, rootMessage(e)), List.of());
        }
    }

    private List<CaRevocationFact> intermediateCaFacts(
            List<X509Certificate> path, List<byte[]> rootCrlBlobs, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, String crlPath, boolean ignoreTruststore,
            String labelPrefix, Map<String, byte[]> externalOcsp) {
        List<CaRevocationFact> facts = new ArrayList<>();
        for (int i = 0; i < path.size(); i++) {
            X509Certificate ca = path.get(i);
            String caLabel = labelPrefix + Messages.get(MsgKey.PROVIDER_LABEL_INTERMEDIATE_CA_SUFFIX, i + 1);
            StageOutcome caRevocation = revocationCascade(ca, rootCrlBlobs, List.of(), null,
                containerCerts, trust, refTime, crlPath, ignoreTruststore, externalOcsp, caLabel);
            facts.add(new CaRevocationFact(caRevocation, ca.getNotAfter().toInstant()));
        }
        return facts;
    }

    public List<CaRevocationFact> intermediateCaRevocationsForBag(
            List<X509Certificate> path, List<byte[]> ocspBlobs, List<byte[]> crlBlobs,
            List<X509Certificate> containerCerts, List<X509Certificate> trust, Instant refTime,
            String crlPath, boolean ignoreTruststore, String labelPrefix, Map<String, byte[]> externalOcsp) {
        List<CaRevocationFact> facts = new ArrayList<>();
        for (int i = 0; i < path.size(); i++) {
            X509Certificate ca = path.get(i);
            String caLabel = labelPrefix + Messages.get(MsgKey.PROVIDER_LABEL_INTERMEDIATE_CA_SUFFIX, i + 1);
            StageOutcome caRevocation = revocationCascadeForBag(ca, ocspBlobs, crlBlobs, containerCerts, trust,
                refTime, crlPath, ignoreTruststore, externalOcsp, caLabel);
            facts.add(new CaRevocationFact(caRevocation, ca.getNotAfter().toInstant()));
        }
        return facts;
    }

    private TimestampInfo timestampInfo(
            ParsedSigner ps, List<X509Certificate> containerCerts, List<X509Certificate> trust,
            Instant refTime, boolean ignoreTruststore, List<byte[]> rootCrlBlobs, String crlPath,
            Map<String, byte[]> externalOcsp) {
        Boolean sigOk = null;
        Boolean bindingOk = null;
        Boolean chainOk = null;
        Boolean tsaOcspOk = null;
        String tsaOcspDetail = null;
        StageOutcome tsaOcspOutcome = null;
        List<CaRevocationFact> tsaIntermediateCaRevocations = List.of();
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
            List<X509Certificate> tsaPath = List.of();
            try {
                tsaPath = buildPath(tsaCert, merge(containerCerts, ps.tsaCertsRaw()), trust, refTime, ignoreTruststore);
                chainOk = true;
            } catch (Exception e) {
                chainOk = false;
                chainDetail = rootMessage(e);
            }
            trace.v(label(ps) + ": " + (Boolean.TRUE.equals(chainOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TSA_CHAIN_OK)
                : Messages.get(MsgKey.PROVIDER_TRACE_TSA_CHAIN_FAIL, chainDetail)));

            tsaIntermediateCaRevocations = Boolean.TRUE.equals(chainOk)
                ? intermediateCaFacts(
                    tsaPath, rootCrlBlobs, merge(containerCerts, ps.tsaCertsRaw()), trust, refTime, crlPath,
                    ignoreTruststore, label(ps) + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX), externalOcsp)
                : List.of();

            AttributeTable tstUt = tstSi.getUnsignedAttributes();
            Attribute revAttr = tstUt == null ? null : tstUt.get(OID_REVVALUES);
            StageOutcome tsaRevocation = revocationCascade(
                tsaCert, rootCrlBlobs, ps.tstCrlBlobs(), revAttr, merge(containerCerts, ps.tsaCertsRaw()),
                trust, refTime, crlPath, ignoreTruststore, externalOcsp,
                label(ps) + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX));
            if (tsaRevocation.status() != CheckStatus.NOT_VERIFIED) {
                tsaOcspOutcome = tsaRevocation;
                tsaOcspOk = tsaRevocation.status() == CheckStatus.PASS;
                tsaOcspDetail = tsaRevocation.detail();
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

            detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_TSA_REVOCATION_PREFIX, tsaOcspDetail);
        }

        boolean valid = !Boolean.FALSE.equals(sigOk) && !Boolean.FALSE.equals(bindingOk)
            && !Boolean.FALSE.equals(chainOk) && !Boolean.FALSE.equals(validityOk)
            && !Boolean.FALSE.equals(tsaOcspOk);

        Instant tsaCertNotAfter = ps.tsaCertRaw() != null ? ps.tsaCertRaw().getNotAfter().toInstant() : null;
        return new TimestampInfo(true, valid, ps.tstGenTime(), detail, ps.tsaTimestampingEkuOk(),
            tsaOcspOutcome, tsaCertNotAfter, tsaIntermediateCaRevocations);
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

    StageOutcome revocationCascade(
            X509Certificate target, List<byte[]> rootCrlBlobs, List<byte[]> ownCrlBlobs,
            Attribute unsignedRevocationValues, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, String crlPath, boolean ignoreTruststore,
            Map<String, byte[]> externalOcsp, String label) {
        StageOutcome outcome = signedDataCrlsOutcome(
            rootCrlBlobs, target, containerCerts, trust, refTime, ignoreTruststore, label);
        if (outcome != null) {
            return outcome;
        }
        outcome = signedDataCrlsOutcome(
            ownCrlBlobs, target, containerCerts, trust, refTime, ignoreTruststore, label);
        if (outcome != null) {
            return outcome;
        }
        outcome = unsignedRevocationValuesOutcome(
            unsignedRevocationValues, target, containerCerts, trust, refTime, ignoreTruststore, label);
        if (outcome != null) {
            return outcome;
        }
        if (crlPath != null) {
            outcome = revocationByCrl(target, trust, containerCerts, refTime, ignoreTruststore, crlPath, label);
            if (outcome != null) {
                return outcome;
            }

        }
        outcome = externalOcspOutcome(
            externalOcsp, target, containerCerts, trust, refTime, ignoreTruststore, label);
        if (outcome != null) {
            return outcome;
        }
        String noOcspNoCrl = Messages.get(MsgKey.PROVIDER_REVOCATION_NO_OCSP_NO_CRL);
        trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_REVOCATION_PREFIX, noOcspNoCrl));
        return new StageOutcome(CheckStatus.NOT_VERIFIED, noOcspNoCrl);
    }

    private StageOutcome externalOcspOutcome(
            Map<String, byte[]> externalOcsp, X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore, String label) {
        if (externalOcsp == null || externalOcsp.isEmpty()) {
            return null;
        }
        byte[] der = externalOcsp.get(certHex(target));
        if (der == null) {
            return null;
        }
        try {
            BasicOCSPResponse resp = BasicOCSPResponse.getInstance(new ASN1InputStream(der).readObject());
            BasicOCSPResp basic = new BasicOCSPResp(resp);
            return revocationOcspOutcome(basic, target, trust, containerCerts, refTime, ignoreTruststore,
                RevocationSource.OCSP_EXTERNAL, label);
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(RevocationSource.OCSP_EXTERNAL,
                Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
        }
    }

    public StageOutcome revocationCascadeForBag(
            X509Certificate target, List<byte[]> ocspBlobs, List<byte[]> crlBlobs,
            List<X509Certificate> containerCerts, List<X509Certificate> trust, Instant refTime,
            String crlPath, boolean ignoreTruststore, Map<String, byte[]> externalOcsp, String label) {
        X509Certificate issuerCert = findBySubject(target.getIssuerX500Principal(), trust, containerCerts);
        if (issuerCert != null) {
            for (byte[] der : ocspBlobs) {
                try {
                    Object obj = new OCSPResp(der).getResponseObject();
                    if (obj instanceof BasicOCSPResp basic
                            && EmbeddedRevocation.matchesOcsp(basic, issuerCert, target)) {
                        return revocationOcspOutcome(basic, target, trust, containerCerts, refTime,
                            ignoreTruststore, RevocationSource.OCSP_EMBEDDED, label);
                    }
                } catch (Exception ignored) {

                }
            }
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", PROV);
            for (byte[] der : crlBlobs) {
                try {
                    X509CRL crl = (X509CRL) cf.generateCRL(new java.io.ByteArrayInputStream(der));
                    if (crl != null && EmbeddedRevocation.matchesCrl(crl, target)) {
                        return revocationByCrlObject(crl, target, trust, containerCerts, refTime, ignoreTruststore,
                            RevocationSource.CRL_EMBEDDED, label, Messages.get(MsgKey.PROVIDER_CRL_EMBEDDED_LABEL));
                    }
                } catch (Exception ignored) {

                }
            }
        } catch (Exception ignored) {

        }
        if (crlPath != null) {
            StageOutcome crlOutcome =
                revocationByCrl(target, trust, containerCerts, refTime, ignoreTruststore, crlPath, label);
            if (crlOutcome != null) {
                return crlOutcome;
            }

        }
        StageOutcome outcome =
            externalOcspOutcome(externalOcsp, target, containerCerts, trust, refTime, ignoreTruststore, label);
        if (outcome != null) {
            return outcome;
        }
        String noOcspNoCrl = Messages.get(MsgKey.PROVIDER_REVOCATION_NO_OCSP_NO_CRL);
        trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_REVOCATION_PREFIX, noOcspNoCrl));
        return new StageOutcome(CheckStatus.NOT_VERIFIED, noOcspNoCrl);
    }

    private static String certHex(X509Certificate cert) {
        try {
            return HexFormat.of().formatHex(cert.getEncoded());
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean hasApplicableRevocationMaterial(
            X509Certificate target, List<byte[]> rootCrlBlobs, List<byte[]> ownCrlBlobs,
            Attribute unsignedRevocationValues, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, String crlPath) {
        if (hasApplicableSignedDataCrls(rootCrlBlobs, target, containerCerts, trust)) {
            return true;
        }
        if (hasApplicableSignedDataCrls(ownCrlBlobs, target, containerCerts, trust)) {
            return true;
        }
        if (unsignedRevocationValues != null
                && (hasRevocationValuesTag(unsignedRevocationValues, TAG_OCSP_VALS)
                    || hasRevocationValuesTag(unsignedRevocationValues, TAG_CRL_VALS))) {
            return true;
        }

        return crlPath != null;
    }

    private static boolean hasApplicableSignedDataCrls(
            List<byte[]> crlBlobs, X509Certificate target,
            List<X509Certificate> containerCerts, List<X509Certificate> trust) {
        if (crlBlobs.isEmpty()) {
            return false;
        }
        List<EmbeddedRevocation.CrlsEntry> entries = EmbeddedRevocation.parseCrlsBlobs(crlBlobs);
        X509Certificate issuerCert = findBySubject(target.getIssuerX500Principal(), trust, containerCerts);
        for (EmbeddedRevocation.CrlsEntry entry : entries) {
            if (entry.ocsp() != null && issuerCert != null
                    && EmbeddedRevocation.matchesOcsp(entry.ocsp(), issuerCert, target)) {
                return true;
            }
            if (entry.crl() != null && EmbeddedRevocation.matchesCrl(entry.crl(), target)) {
                return true;
            }
        }
        return false;
    }

    private record TstFacts(String digestOid, Attribute revAttr) {
    }

    private static TstFacts tstFacts(ParsedSigner ps) {
        try {
            AttributeTable ut = ps.signerInfo().getUnsignedAttributes();
            Attribute tstAttr = ut == null ? null : ut.get(OID_SIGTST);
            if (tstAttr == null) {
                return null;
            }
            ContentInfo ci = ContentInfo.getInstance(tstAttr.getAttrValues().getObjectAt(0));
            CMSSignedData tstCms = new CMSSignedData(ci);
            SignerInformation tstSi = (SignerInformation) tstCms.getSignerInfos().getSigners().iterator().next();
            AttributeTable tstUt = tstSi.getUnsignedAttributes();
            Attribute revAttr = tstUt == null ? null : tstUt.get(OID_REVVALUES);
            return new TstFacts(tstSi.getDigestAlgOID(), revAttr);
        } catch (Exception e) {
            return null;
        }
    }

    private static TstFacts markTstFacts(ArchiveTs.ParsedArchiveTimestamp mark) {
        try {
            var asn1 = new ASN1InputStream(mark.tstDer).readObject();
            ContentInfo ci = ContentInfo.getInstance(asn1);
            CMSSignedData tstCms = new CMSSignedData(ci);
            SignerInformation tstSi = (SignerInformation) tstCms.getSignerInfos().getSigners().iterator().next();
            AttributeTable tstUt = tstSi.getUnsignedAttributes();
            Attribute revAttr = tstUt == null ? null : tstUt.get(OID_REVVALUES);
            return new TstFacts(tstSi.getDigestAlgOID(), revAttr);
        } catch (Exception e) {
            return null;
        }
    }

    public List<OnlineRevocationRequest> onlineRevocationRequests(
            VerificationRequest request, byte[] container) {
        List<X509Certificate> trust = ManifestTrust.loadCertificates(request.trust().roots());
        ParsedContainer parsed = Parsing.parseContainer(container, trust);
        boolean ignoreTruststore = request.ignoreTruststore();
        List<X509Certificate> containerCerts = parsed.containerCerts();
        String crlPath = request.trust().crls().isEmpty() ? null : request.trust().crls().get(0);

        List<OnlineRevocationRequest> requests = new ArrayList<>();
        for (ParsedSigner ps : parsed.signers()) {
            if (ps.signerCertRaw() == null) {
                continue;
            }
            X509Certificate signerCert = ps.signerCertRaw();
            AnchorInfo anchor = resolveAnchor(signerCert, containerCerts, trust, ignoreTruststore);
            if (!anchor.anchored()) {
                continue;
            }
            Instant refTime = ps.hasTimestamp() && ps.tstGenTime() != null ? ps.tstGenTime() : Instant.now();
            AttributeTable ut = ps.signerInfo().getUnsignedAttributes();
            Attribute signerRevAttr = ut == null ? null : ut.get(OID_REVVALUES);
            String signerDigestOid = ps.signerInfo().getDigestAlgOID();
            String signerLabel = label(ps);

            addRequestIfNeeded(requests, signerCert, parsed.crlBlobs(), List.of(), signerRevAttr,
                containerCerts, trust, crlPath, signerDigestOid, signerLabel, ps.index(), Stage.REVOCATION);
            addCaPathRequests(requests, signerCert, containerCerts, trust, refTime, ignoreTruststore,
                parsed.crlBlobs(), crlPath, signerDigestOid, signerLabel, ps.index(), Stage.CHAIN);

            if (!ps.hasTimestamp() || ps.tsaCertRaw() == null) {
                continue;
            }
            X509Certificate tsaCert = ps.tsaCertRaw();
            List<X509Certificate> tsaPool = merge(containerCerts, ps.tsaCertsRaw());
            String tsaLabel = signerLabel + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX);
            TstFacts tstFacts = tstFacts(ps);
            if (tstFacts != null) {
                addRequestIfNeeded(requests, tsaCert, parsed.crlBlobs(), ps.tstCrlBlobs(), tstFacts.revAttr(),
                    tsaPool, trust, crlPath, tstFacts.digestOid(), tsaLabel, ps.index(), Stage.TIMESTAMP);
                addCaPathRequests(requests, tsaCert, tsaPool, trust, refTime, ignoreTruststore,
                    parsed.crlBlobs(), crlPath, tstFacts.digestOid(), tsaLabel, ps.index(), Stage.TIMESTAMP);
            }

            for (ArchiveTs.ParsedArchiveTimestamp mark : ps.archiveMarks()) {
                if (mark.parseError != null || mark.tsaCert == null) {
                    continue;
                }
                List<X509Certificate> markPool = merge(containerCerts, mark.tsaCerts);
                String markLabel = signerLabel
                    + Messages.get(MsgKey.PROVIDER_LABEL_ARCHIVE_MARK_SUFFIX, mark.position + 1)
                    + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX);
                TstFacts markFacts = markTstFacts(mark);
                if (markFacts == null) {
                    continue;
                }
                addRequestIfNeeded(requests, mark.tsaCert, parsed.crlBlobs(), List.of(), markFacts.revAttr(),
                    markPool, trust, crlPath, markFacts.digestOid(), markLabel, ps.index(),
                    Stage.ARCHIVE_TIMESTAMP);
                addCaPathRequests(requests, mark.tsaCert, markPool, trust, mark.genTime, ignoreTruststore,
                    parsed.crlBlobs(), crlPath, markFacts.digestOid(), markLabel, ps.index(),
                    Stage.ARCHIVE_TIMESTAMP);
            }
        }
        return requests;
    }

    private static void addRequestIfNeeded(
            List<OnlineRevocationRequest> requests, X509Certificate target, List<byte[]> rootCrlBlobs,
            List<byte[]> ownCrlBlobs, Attribute unsignedRevocationValues, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, String crlPath, String digestOid, String label, int signerIndex,
            Stage stage) {
        if (digestOid == null) {
            return;
        }
        if (hasApplicableRevocationMaterial(
                target, rootCrlBlobs, ownCrlBlobs, unsignedRevocationValues, containerCerts, trust, crlPath)) {
            return;
        }
        X509Certificate issuer = findBySubject(target.getIssuerX500Principal(), trust, containerCerts);
        if (issuer == null) {
            return;
        }
        requests.add(new OnlineRevocationRequest(target, issuer, digestOid, label, signerIndex, stage));
    }

    private static void addCaPathRequests(
            List<OnlineRevocationRequest> requests, X509Certificate pathTarget,
            List<X509Certificate> containerCerts, List<X509Certificate> trust, Instant refTime,
            boolean ignoreTruststore, List<byte[]> rootCrlBlobs, String crlPath, String digestOid,
            String labelPrefix, int signerIndex, Stage stage) {
        List<X509Certificate> path;
        try {
            path = buildPath(pathTarget, containerCerts, trust, refTime, ignoreTruststore);
        } catch (Exception e) {
            return;
        }
        for (int i = 0; i < path.size(); i++) {
            X509Certificate ca = path.get(i);
            String caLabel = labelPrefix + Messages.get(MsgKey.PROVIDER_LABEL_INTERMEDIATE_CA_SUFFIX, i + 1);
            addRequestIfNeeded(requests, ca, rootCrlBlobs, List.of(), null, containerCerts, trust, crlPath,
                digestOid, caLabel, signerIndex, stage);
        }
    }

    StageOutcome revocationOutcome(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, String crlPath, boolean ignoreTruststore,
            List<byte[]> crlBlobs, Map<String, byte[]> externalOcsp) {
        AttributeTable ut = ps.signerInfo().getUnsignedAttributes();
        Attribute revAttr = ut == null ? null : ut.get(OID_REVVALUES);
        return revocationCascade(signerCert, crlBlobs, List.of(), revAttr, containerCerts, trust,
            refTime, crlPath, ignoreTruststore, externalOcsp, label(ps));
    }

    private StageOutcome signedDataCrlsOutcome(
            List<byte[]> crlBlobs, X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore, String label) {
        if (crlBlobs.isEmpty()) {
            return null;
        }
        List<EmbeddedRevocation.CrlsEntry> entries = EmbeddedRevocation.parseCrlsBlobs(crlBlobs);
        X509Certificate issuerCert = findBySubject(target.getIssuerX500Principal(), trust, containerCerts);
        List<StageOutcome> outcomes = new ArrayList<>();
        for (EmbeddedRevocation.CrlsEntry entry : entries) {
            if (entry.ocsp() != null && issuerCert != null
                    && EmbeddedRevocation.matchesOcsp(entry.ocsp(), issuerCert, target)) {
                outcomes.add(revocationOcspOutcome(entry.ocsp(), target, trust, containerCerts, refTime,
                    ignoreTruststore, RevocationSource.OCSP_CONTAINER, label));
            } else if (entry.crl() != null && EmbeddedRevocation.matchesCrl(entry.crl(), target)) {
                outcomes.add(revocationByCrlObject(entry.crl(), target, trust, containerCerts, refTime,
                    ignoreTruststore, RevocationSource.CRL_CONTAINER, label,
                    Messages.get(MsgKey.PROVIDER_CRL_CONTAINER_LABEL)));
            }
        }
        return outcomes.isEmpty() ? null : combineByRevokedWins(outcomes);
    }

    static StageOutcome combineByRevokedWins(List<StageOutcome> outcomes) {
        return kz.edscheck.provider.RevocationCombine.combineByRevokedWins(outcomes);
    }

    private StageOutcome unsignedRevocationValuesOutcome(
            Attribute revAttr, X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore, String label) {
        if (revAttr == null) {
            return null;
        }
        if (hasRevocationValuesTag(revAttr, TAG_OCSP_VALS)) {
            return revocationOcspOutcome(revAttr, target, trust, containerCerts, refTime,
                ignoreTruststore, RevocationSource.OCSP_EMBEDDED, label);
        }
        if (hasRevocationValuesTag(revAttr, TAG_CRL_VALS)) {
            X509CRL embedded = extractEmbeddedCrlForSigner(revAttr, target, label);
            if (embedded != null) {
                return revocationByCrlObject(embedded, target, trust, containerCerts, refTime,
                    ignoreTruststore, RevocationSource.CRL_EMBEDDED, label,
                    Messages.get(MsgKey.PROVIDER_CRL_EMBEDDED_LABEL));
            }

            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_EMBEDDED_NO_MATCH));
            return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_EMBEDDED)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_MISMATCH)).build();
        }
        return null;
    }

    private StageOutcome revocationOcspOutcome(
            Attribute revValues, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore,
            RevocationSource source, String label) {
        List<BasicOCSPResp> candidates;
        try {
            candidates = extractBasicOcspCandidates(revValues);
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
        }
        if (candidates.isEmpty()) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_NOT_EXTRACTED));
            return new StageOutcome(CheckStatus.NOT_VERIFIED,
                Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_NOT_EXTRACTED));
        }
        BasicOCSPResp basic = selectMatchingOcsp(candidates, signerCert, trust, containerCerts);
        return revocationOcspOutcome(
            basic, signerCert, trust, containerCerts, refTime, ignoreTruststore, source, label);
    }

    static BasicOCSPResp selectMatchingOcsp(
            List<BasicOCSPResp> candidates, X509Certificate target,
            List<X509Certificate> trust, List<X509Certificate> containerCerts) {
        if (candidates.size() == 1) {
            return candidates.get(0);
        }
        X509Certificate issuerCert = findBySubject(target.getIssuerX500Principal(), trust, containerCerts);
        if (issuerCert != null) {
            for (BasicOCSPResp candidate : candidates) {
                if (EmbeddedRevocation.matchesOcsp(candidate, issuerCert, target)) {
                    return candidate;
                }
            }
        }
        return candidates.get(0);
    }

    private StageOutcome revocationOcspOutcome(
            BasicOCSPResp basic, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore,
            RevocationSource source, String label) {
        try {
            X509Certificate[] respCerts = basic.getCerts(PROV);
            X509Certificate responder = (respCerts != null && respCerts.length > 0) ? respCerts[0] : null;
            if (responder == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_MISSING));
                return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_RESPONDER_MISSING));
            }
            if (!basic.verify(responder.getPublicKey(), PROV)) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_SIGNATURE_FAILED));
                return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_SIGNATURE_FAILED));
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_SIGNATURE_OK));
            if (!responder.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal())
                    || !hasOcspSigning(responder)) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_UNAUTHORIZED));
                return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_RESPONDER_UNAUTHORIZED));
            }
            List<X509Certificate> respPool = new ArrayList<>(containerCerts);
            respPool.addAll(Arrays.asList(respCerts));
            try {
                buildPath(responder, respPool, trust, refTime, ignoreTruststore);
            } catch (Exception e) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_CHAIN_FAILED,
                    rootMessage(e)));

                return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_CHAIN_PREFIX, rootMessage(e)));
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_AUTHORIZED,
                responder.getSubjectX500Principal().getName()));

            X509Certificate issuerCert =
                findBySubject(signerCert.getIssuerX500Principal(), trust, containerCerts);
            if (issuerCert == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_ISSUER_NOT_FOUND));
                return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_ISSUER_NOT_FOUND));
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
                return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_CERTID_MISMATCH));
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_CERTID_MATCH));

            Object status = match.getCertStatus();
            Instant thisUpdate = toInstant(match.getThisUpdate());
            Instant nextUpdate = toInstant(match.getNextUpdate());
            if (status == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_GOOD,
                    traceDt(thisUpdate), traceDt(nextUpdate)));
                return StageOutcome.of(CheckStatus.PASS).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_GOOD))
                    .validFrom(thisUpdate).validUntil(nextUpdate).build();
            }
            if (status instanceof RevokedStatus rs) {
                Instant revokedAt = toInstant(rs.getRevocationTime());
                String reason = rs.hasRevocationReason() ? reasonLabel(rs.getRevocationReason()) : null;
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_REVOKED,
                    traceDt(revokedAt), reason));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_REVOKED))
                    .validFrom(thisUpdate).validUntil(nextUpdate)
                    .revokedAt(revokedAt).revokedReason(reason).build();
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_UNKNOWN));
            return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_STATUS_UNKNOWN));
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(source, Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
        }
    }

    private static StageOutcome revFail(RevocationSource source, String detail) {
        return StageOutcome.of(CheckStatus.FAIL).source(source).detail(detail).build();
    }

    StageOutcome revocationByCrl(
            ParsedSigner ps, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore,
            String crlPath) {
        return revocationByCrl(signerCert, trust, containerCerts, refTime, ignoreTruststore, crlPath, label(ps));
    }

    private StageOutcome revocationByCrl(
            X509Certificate target, List<X509Certificate> trust, List<X509Certificate> containerCerts,
            Instant refTime, boolean ignoreTruststore, String crlPath, String label) {
        X509CRL crl;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", PROV);
            try (InputStream in = new FileInputStream(crlPath)) {
                crl = (X509CRL) cf.generateCRL(in);
            }
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_PARSE_FAILED, crlPath, rootMessage(e)));
            return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_FILE)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_PARSE_FAILED, rootMessage(e))).build();
        }
        return revocationByCrlObject(crl, target, trust, containerCerts, refTime, ignoreTruststore,
            RevocationSource.CRL_FILE, label, crlPath);
    }

    StageOutcome revocationByCrlObject(
            X509CRL crl, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore,
            RevocationSource source, String signerLabel, String crlLabel) {
        try {
            if (!crl.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal())) {
                trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_MISMATCH, crlLabel));
                return null;
            }
            X509Certificate issuer = findBySubject(crl.getIssuerX500Principal(), trust, containerCerts);
            if (issuer == null) {
                trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_NOT_FOUND, crlLabel));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_NOT_FOUND)).build();
            }
            try {
                crl.verify(issuer.getPublicKey(), PROV);
            } catch (Exception e) {
                trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_SIGNATURE_FAILED,
                    crlLabel, rootMessage(e)));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_SIGNATURE_FAILED, rootMessage(e))).build();
            }
            trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_SIGNATURE_OK, crlLabel));
            if (!crlSignOk(issuer)) {
                trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_NO_CRL_SIGN, crlLabel));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_NO_CRL_SIGN)).build();
            }
            try {
                buildPath(issuer, containerCerts, trust, refTime, ignoreTruststore);
            } catch (Exception e) {
                trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_CHAIN_FAILED,
                    crlLabel, rootMessage(e)));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_CHAIN_FAILED, rootMessage(e))).build();
            }
            trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_CHAIN_OK, crlLabel));
            Instant thisUpdate = toInstant(crl.getThisUpdate());
            Instant nextUpdate = toInstant(crl.getNextUpdate());
            X509CRLEntry entry = crl.getRevokedCertificate(signerCert);
            if (entry != null) {
                CRLReason r = entry.getRevocationReason();
                String reason = r != null ? reasonLabel(r.ordinal()) : null;
                trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_REVOKED, reason));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_REVOKED))
                    .validFrom(thisUpdate).validUntil(nextUpdate)
                    .revokedAt(toInstant(entry.getRevocationDate())).revokedReason(reason).build();
            }
            trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_NOT_REVOKED,
                traceDt(thisUpdate), traceDt(nextUpdate)));
            return StageOutcome.of(CheckStatus.PASS).source(source)
                .validFrom(thisUpdate).validUntil(nextUpdate).build();
        } catch (Exception e) {
            trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_PARSE_FAILED, crlLabel, rootMessage(e)));
            return StageOutcome.of(CheckStatus.FAIL).source(source)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_PARSE_FAILED, rootMessage(e))).build();
        }
    }

    static List<BasicOCSPResp> extractBasicOcspCandidates(Attribute revValues) throws Exception {

        ASN1Sequence rv = ASN1Sequence.getInstance(revValues.getAttrValues().getObjectAt(0));
        for (int i = 0; i < rv.size(); i++) {
            DEREncodable e = rv.getObjectAt(i);
            if (e instanceof ASN1TaggedObject t && t.getTagNo() == 1) {
                ASN1Sequence ocspVals = ASN1Sequence.getInstance(t, true);
                List<BasicOCSPResp> out = new ArrayList<>();
                for (int j = 0; j < ocspVals.size(); j++) {
                    BasicOCSPResponse resp = BasicOCSPResponse.getInstance(ocspVals.getObjectAt(j));
                    out.add(new BasicOCSPResp(resp));
                }
                return out;
            }
        }
        return List.of();
    }

    private static boolean hasRevocationValuesTag(Attribute revValues, int tagNo) {
        try {
            ASN1Sequence rv = ASN1Sequence.getInstance(revValues.getAttrValues().getObjectAt(0));
            for (int i = 0; i < rv.size(); i++) {
                DEREncodable e = rv.getObjectAt(i);
                if (e instanceof ASN1TaggedObject t && t.getTagNo() == tagNo) {
                    ASN1Sequence inner = ASN1Sequence.getInstance(t, true);
                    if (inner.size() > 0) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception ignored) {
            return false;
        }
    }

    X509CRL extractEmbeddedCrlForSigner(Attribute revValues, X509Certificate signerCert, String signerLabel) {
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509", PROV);
        } catch (Exception e) {
            return null;
        }
        try {
            ASN1Sequence rv = ASN1Sequence.getInstance(revValues.getAttrValues().getObjectAt(0));
            int index = 0;
            for (int i = 0; i < rv.size(); i++) {
                DEREncodable e = rv.getObjectAt(i);
                if (!(e instanceof ASN1TaggedObject t) || t.getTagNo() != TAG_CRL_VALS) {
                    continue;
                }
                ASN1Sequence crlVals = ASN1Sequence.getInstance(t, true);
                for (int j = 0; j < crlVals.size(); j++) {
                    index++;
                    DEREncodable certListObj = crlVals.getObjectAt(j);
                    X509CRL crl;
                    try {
                        byte[] der = certListObj.getDERObject().getDEREncoded();
                        crl = (X509CRL) cf.generateCRL(new java.io.ByteArrayInputStream(der));
                    } catch (Exception parseEx) {
                        trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_EMBEDDED_SKIPPED,
                            index, rootMessage(parseEx)));
                        continue;
                    }
                    if (crl != null && crl.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal())) {
                        return crl;
                    }
                    trace.v(signerLabel + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_EMBEDDED_SKIPPED,
                        index, Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_MISMATCH)));
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private List<ArchiveMarkOutcome> archiveOutcome(
            ParsedSigner ps, List<X509Certificate> containerCerts, List<X509Certificate> trust,
            boolean ignoreTruststore, List<byte[]> rootCrlBlobs, String crlPath,
            Map<String, byte[]> externalOcsp) {
        List<ArchiveMarkOutcome> results = new ArrayList<>();
        for (ArchiveTs.ParsedArchiveTimestamp mark : ps.archiveMarks()) {
            String hashFailure = null;
            Boolean sigOk = null;
            Boolean chainOk = null;
            StageOutcome ownRevocation = null;
            Instant tsaCertNotAfter = null;
            List<CaRevocationFact> caFacts = List.of();
            if (mark.parseError == null) {
                List<X509Certificate> markPath = List.of();
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
                        markPath = buildPath(mark.tsaCert, merge(containerCerts, mark.tsaCerts), trust,
                            mark.genTime, ignoreTruststore);
                        chainOk = true;
                    } catch (Exception e) {
                        chainOk = false;
                    }
                } catch (Exception e) {
                    sigOk = false;
                    chainOk = false;
                }

                if (Boolean.TRUE.equals(chainOk)) {
                    tsaCertNotAfter = mark.tsaCert.getNotAfter().toInstant();
                    List<X509Certificate> pool = merge(containerCerts, mark.tsaCerts);
                    String markLabel =
                        label(ps) + Messages.get(MsgKey.PROVIDER_LABEL_ARCHIVE_MARK_SUFFIX, mark.position + 1);

                    ownRevocation = revocationCascade(mark.tsaCert, rootCrlBlobs, List.of(), null,
                        pool, trust, mark.genTime, crlPath, ignoreTruststore, externalOcsp,
                        markLabel + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX));
                    caFacts = intermediateCaFacts(
                        markPath, rootCrlBlobs, pool, trust, mark.genTime, crlPath, ignoreTruststore, markLabel,
                        externalOcsp);
                }

                List<byte[]> certHashes = digestGroup(mark.certBlobs, mark.hashIndAlgOid);
                List<byte[]> crlHashes = digestGroup(mark.crlBlobs, mark.hashIndAlgOid);
                List<byte[]> attrHashes = digestGroup(mark.attrBlobs, mark.hashIndAlgOid);
                byte[] imprint = digestOne(mark.imprintBlob, mark.imprintAlgOid);
                hashFailure = ArchiveTs.evaluateHashes(mark, certHashes, crlHashes, attrHashes, imprint);
            }

            Boolean tsaValidityOk = ArchiveTs.markTsaCertInValidity(mark);
            String cryptoSummary = ArchiveTs.markFailure(
                mark.parseError, sigOk, chainOk, chainOk, tsaValidityOk, mark.tsaEkuOk, null, hashFailure);

            trace.v(label(ps) + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ARCHIVE_MARK,
                mark.position + 1, cryptoSummary == null
                    ? Messages.get(MsgKey.PROVIDER_TRACE_ARCHIVE_MARK_OK) : cryptoSummary));
            results.add(new ArchiveMarkOutcome(mark.position, mark.parseError, mark.genTime, sigOk, chainOk,
                tsaValidityOk, mark.tsaEkuOk, hashFailure, ownRevocation, tsaCertNotAfter, caFacts));
        }
        return results;
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

    public record AnchorInfo(
            boolean anchored, X509Certificate caCert, String detail, X500Principal signerIssuerName) {
    }

    public static AnchorInfo resolveAnchor(
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

    public static List<X509Certificate> buildPath(
            X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore) throws Exception {
        return buildPath(target, containerCerts, trust, refTime == null ? null : Date.from(refTime), ignoreTruststore);
    }

    private static List<X509Certificate> buildPath(
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
        PKIXCertPathBuilderResult pkixResult = (PKIXCertPathBuilderResult) result;

        if (ignoreTruststore) {
            X509Certificate rootUsed = pkixResult.getTrustAnchor().getTrustedCert();
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

        List<? extends java.security.cert.Certificate> pathCerts = pkixResult.getCertPath().getCertificates();
        List<X509Certificate> intermediates = new ArrayList<>();
        for (int i = 1; i < pathCerts.size(); i++) { 
            intermediates.add((X509Certificate) pathCerts.get(i));
        }
        return intermediates;
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

    public static X509Certificate findBySubject(
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

    public static boolean hasOcspSigning(X509Certificate cert) {
        try {
            List<String> eku = cert.getExtendedKeyUsage();
            return eku != null && eku.contains(OID_OCSP_SIGNING);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean crlSignOk(X509Certificate cert) {
        boolean[] ku = cert.getKeyUsage();
        return ku == null || (ku.length > 6 && ku[6]);
    }

    public static Instant toInstant(Date d) {
        return d == null ? null : d.toInstant();
    }

    public static String reasonLabel(int code) {
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
