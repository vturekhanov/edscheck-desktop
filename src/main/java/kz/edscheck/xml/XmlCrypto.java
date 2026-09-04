package kz.edscheck.xml;

import static kz.edscheck.provider.jce.JceVerificationProvider.buildPath;
import static kz.edscheck.provider.jce.JceVerificationProvider.findBySubject;
import static kz.edscheck.provider.jce.JceVerificationProvider.resolveAnchor;
import static kz.edscheck.provider.jce.JceVerificationProvider.toInstant;
import static kz.edscheck.provider.jce.JceVerificationProvider.verifySignerInfo;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.keyresolver.KeyResolver;
import org.apache.xml.security.signature.MissingResourceFailureException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.CaRevocationFact;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.TimestampInfo;
import kz.edscheck.provider.jce.JceVerificationProvider.AnchorInfo;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.Authorities;
import kz.edscheck.trust.DigestAlgorithms;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import kz.edscheck.trust.ActiveBackend;

final class XmlCrypto {
    private static final String XPATH_FILTER2_TRANSFORM_CLASS =
        "org.apache.xml.security.transforms.implementations.TransformXPath2Filter";

    private static final String ESF_SIGNATURE_ALGORITHM = "ECGOST3410-2015-512";

    private static final String GOST_DIGEST_URI_2015 =
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
    private static final String GOST_DIGEST_JCE_NAME_2015 = "GOST3411-2015-512";
    private static final String GOST_DIGEST_URI_2004 = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    private static final String GOST_DIGEST_JCE_NAME_2004 = "GOST34311";

    private static volatile boolean initialized = false;

    private XmlCrypto() {
    }

    static synchronized void ensureInitialized() {
        if (initialized) {
            return;
        }

        Init.init();
        JCEMapper.setProviderId(ActiveBackend.current().jceProviderName());
        JCEMapper.register(GOST_DIGEST_URI_2015,
            new JCEMapper.Algorithm(null, GOST_DIGEST_JCE_NAME_2015, "MessageDigest"));
        JCEMapper.register(GOST_DIGEST_URI_2004,
            new JCEMapper.Algorithm(null, GOST_DIGEST_JCE_NAME_2004, "MessageDigest"));
        JCEMapper.register(GostSignatureAlgorithm.URI_2015,
            new JCEMapper.Algorithm(null, GostSignatureAlgorithm.JCE_NAME_2015, "Signature"));
        JCEMapper.register(GostSignatureAlgorithm.URI_2004,
            new JCEMapper.Algorithm(null, GostSignatureAlgorithm.JCE_NAME_2004, "Signature"));
        try {
            SignatureAlgorithm.register(GostSignatureAlgorithm.URI_2015,
                GostSignatureAlgorithm.GostR34102015GostR34112015512.class);
            SignatureAlgorithm.register(GostSignatureAlgorithm.URI_2004,
                GostSignatureAlgorithm.Gost34310Gost34311.class);
            Transform.register(XmlSecurityChecks.XPATH_FILTER2_NS, XPATH_FILTER2_TRANSFORM_CLASS);
        } catch (AlgorithmAlreadyRegisteredException e) {

        } catch (Exception e) {

            throw new IllegalStateException(e);
        }
        KeyResolver.register(new GostX509KeyResolver(), false);
        initialized = true;
    }

    static TimestampInfo verifyTimestamp(
            ParsedXmlSignature ps, Element signatureElement, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore) {
        return verifyTimestamp(ps, signatureElement, containerCerts, trust, refTime, ignoreTruststore,
            null, Map.of(), Trace.NONE, "");
    }

    static TimestampInfo verifyTimestamp(
            ParsedXmlSignature ps, Element signatureElement, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore, String crlPath,
            Map<String, byte[]> externalOcsp, Trace trace, String label) {
        if (ps.signatureTimestampToken() == null) {
            return TimestampInfo.absent();
        }
        ensureInitialized();
        try {
            ASN1InputStream ain = new ASN1InputStream(ps.signatureTimestampToken());
            ContentInfo ci = ContentInfo.getInstance(ain.readObject());
            CMSSignedData tstCms = new CMSSignedData(ci);
            SignerInformation tstSi = tstCms.getSignerInfos().getSigners().iterator().next();
            TimeStampToken tst = new TimeStampToken(ci);
            Instant genTime = tst.getTimeStampInfo().getGenTime() == null ? null
                : tst.getTimeStampInfo().getGenTime().toInstant();

            Store<X509CertificateHolder> certStore = tstCms.getCertificates();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> tsaCertColl = certStore.getMatches(tstSi.getSID());
            X509Certificate tsaCert = tsaCertColl.isEmpty() ? null : converter.getCertificate(tsaCertColl.iterator().next());
            List<X509Certificate> tsaCerts = new ArrayList<>();
            for (X509CertificateHolder h : certStore.getMatches(null)) {
                tsaCerts.add(converter.getCertificate(h));
            }
            String tsaCertName = tsaCert == null ? "?" : tsaCert.getSubjectX500Principal().getName();

            Boolean sigOk;
            try {
                sigOk = tsaCert != null && verifySignerInfo(tstSi, tsaCert, ActiveBackend.current().jceProviderName());
            } catch (Exception e) {
                sigOk = false;
            }
            trace.v(label + ": " + (Boolean.TRUE.equals(sigOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TST_SIGNATURE_OK, tsaCertName)
                : Messages.get(MsgKey.PROVIDER_TRACE_TST_SIGNATURE_FAIL, tsaCertName)));

            String jceName = DigestAlgorithms.jceName(tst.getTimeStampInfo().getMessageImprintAlgOID().getId());
            Boolean bindingOk;
            if (jceName == null || ps.signatureTimestampCanonicalizationMethod() == null) {
                bindingOk = false;
            } else {
                byte[] canonSv = canonicalizeSignatureValue(
                    signatureElement, ps.signatureTimestampCanonicalizationMethod());
                MessageDigest md = MessageDigest.getInstance(jceName, ActiveBackend.current().jceProviderName());
                byte[] calc = md.digest(canonSv);
                bindingOk = Arrays.equals(calc, tst.getTimeStampInfo().getMessageImprintDigest());
            }
            trace.v(label + ": " + (Boolean.TRUE.equals(bindingOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TST_BINDING_OK, jceName)
                : Messages.get(MsgKey.PROVIDER_TRACE_TST_BINDING_FAIL, jceName)));

            Boolean chainOk;
            String chainDetail = null;
            List<X509Certificate> tsaPath = List.of();
            List<X509Certificate> pool = new ArrayList<>(containerCerts);
            pool.addAll(tsaCerts);
            try {
                tsaPath = buildPath(tsaCert, pool, trust, refTime, ignoreTruststore);
                chainOk = true;
            } catch (Exception e) {
                chainOk = false;
                chainDetail = rootMessage(e);
            }
            trace.v(label + ": " + (Boolean.TRUE.equals(chainOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TSA_CHAIN_OK)
                : Messages.get(MsgKey.PROVIDER_TRACE_TSA_CHAIN_FAIL, chainDetail)));

            Boolean validityOk = tsaCertInValidity(tsaCert, genTime);
            if (validityOk != null) {
                trace.v(label + ": " + (validityOk
                    ? Messages.get(MsgKey.PROVIDER_TRACE_TSA_VALIDITY_OK, traceDt(genTime))
                    : Messages.get(MsgKey.PROVIDER_TRACE_TSA_VALIDITY_FAIL, traceDt(genTime))));
            }

            String tsaLabel = label + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX);
            kz.edscheck.provider.jce.JceVerificationProvider kp = new kz.edscheck.provider.jce.JceVerificationProvider(trace);

            List<CaRevocationFact> intermediateCaRevocations = Boolean.TRUE.equals(chainOk)
                ? kp.intermediateCaRevocationsForBag(tsaPath, ps.ocspValues(), ps.crlValues(), pool, trust,
                    refTime, crlPath, ignoreTruststore, tsaLabel, externalOcsp)
                : List.of();

            StageOutcome tsaRevocation = kp.revocationCascadeForBag(tsaCert, ps.ocspValues(), ps.crlValues(),
                pool, trust, refTime, crlPath, ignoreTruststore, externalOcsp, tsaLabel);
            StageOutcome tsaOcspOutcome = null;
            Boolean tsaOcspOk = null;
            String tsaOcspDetail = null;
            if (tsaRevocation.status() != CheckStatus.NOT_VERIFIED) {
                tsaOcspOutcome = tsaRevocation;
                tsaOcspOk = tsaRevocation.status() == CheckStatus.PASS;
                tsaOcspDetail = tsaRevocation.detail();
            }

            String detail = null;
            if (!Boolean.TRUE.equals(sigOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_SIG_FAILED);
            } else if (!Boolean.TRUE.equals(chainOk)) {
                detail = chainDetail;
            } else if (Boolean.FALSE.equals(bindingOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_BINDING_FAILED);
            } else if (Boolean.FALSE.equals(validityOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_CERT_EXPIRED);
            } else if (Boolean.FALSE.equals(tsaOcspOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_TSA_REVOCATION_PREFIX, tsaOcspDetail);
            }

            boolean valid = !Boolean.FALSE.equals(sigOk) && !Boolean.FALSE.equals(bindingOk)
                && !Boolean.FALSE.equals(chainOk) && !Boolean.FALSE.equals(validityOk)
                && !Boolean.FALSE.equals(tsaOcspOk);

            Instant tsaCertNotAfter = tsaCert != null ? tsaCert.getNotAfter().toInstant() : null;
            return new TimestampInfo(true, valid, genTime, detail, null, tsaOcspOutcome, tsaCertNotAfter,
                intermediateCaRevocations);
        } catch (Exception e) {
            String detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_PARSE_FAILED, e.getMessage());
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_TST_PARSE_FAILED, detail));
            return new TimestampInfo(true, false, null, detail, null, null);
        }
    }

    record TsaCertInfo(X509Certificate tsaCert, List<X509Certificate> tsaCerts) {
    }

    static TsaCertInfo peekTsaCert(byte[] tstDer) {
        try {
            ASN1InputStream ain = new ASN1InputStream(tstDer);
            ContentInfo ci = ContentInfo.getInstance(ain.readObject());
            CMSSignedData tstCms = new CMSSignedData(ci);
            SignerInformation tstSi = tstCms.getSignerInfos().getSigners().iterator().next();
            Store<X509CertificateHolder> certStore = tstCms.getCertificates();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> tsaCertColl = certStore.getMatches(tstSi.getSID());
            X509Certificate tsaCert = tsaCertColl.isEmpty() ? null : converter.getCertificate(tsaCertColl.iterator().next());
            List<X509Certificate> tsaCerts = new ArrayList<>();
            for (X509CertificateHolder h : certStore.getMatches(null)) {
                tsaCerts.add(converter.getCertificate(h));
            }
            return new TsaCertInfo(tsaCert, tsaCerts);
        } catch (Exception e) {
            return new TsaCertInfo(null, List.of());
        }
    }

    static Boolean tsaCertInValidity(X509Certificate tsaCert, Instant genTime) {
        if (tsaCert == null || genTime == null) {
            return null;
        }
        Instant notBefore = tsaCert.getNotBefore().toInstant();
        Instant notAfter = tsaCert.getNotAfter().toInstant();
        return !genTime.isBefore(notBefore) && !genTime.isAfter(notAfter);
    }

    private static byte[] canonicalizeSignatureValue(Element signatureElement, String c14nAlgorithm)
            throws Exception {
        NodeList svNodes = signatureElement.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "SignatureValue");
        if (svNodes.getLength() == 0) {
            throw new IllegalStateException("ds:SignatureValue не найден");
        }
        org.apache.xml.security.c14n.Canonicalizer c14n =
            org.apache.xml.security.c14n.Canonicalizer.getInstance(c14nAlgorithm);
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        c14n.canonicalizeSubtree(svNodes.item(0), baos);
        return baos.toByteArray();
    }

    static XmlIntegrityResult verifyIntegrity(
            Document doc, Element signatureElement, X509Certificate signerCert, String baseUri) {
        return verifyIntegrity(doc, signatureElement, signerCert, baseUri, null, Trace.NONE, "");
    }

    static XmlIntegrityResult verifyIntegrity(
            Document doc, Element signatureElement, X509Certificate signerCert, String baseUri,
            DocumentSource externalDocument) {
        return verifyIntegrity(doc, signatureElement, signerCert, baseUri, externalDocument, Trace.NONE, "");
    }

    static XmlIntegrityResult verifyIntegrity(
            Document doc, Element signatureElement, X509Certificate signerCert, String baseUri,
            DocumentSource externalDocument, Trace trace, String label) {
        ensureInitialized();
        registerIds(doc);
        XMLSignature sig;
        try {
            sig = new XMLSignature(signatureElement, baseUri == null ? "" : baseUri);
        } catch (XMLSecurityException e) {
            String detail = Messages.get(MsgKey.XML_STRUCTURE_NOT_XMLDSIG);
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_ERROR, detail));
            return new XmlIntegrityResult(IntegrityOutcome.INVALID, List.of(), detail);
        }
        if (externalDocument != null) {
            sig.addResourceResolver(new ExternalDocumentResolver(externalDocument));
        }
        try {
            boolean valid = signerCert != null && sig.checkSignatureValue(signerCert);
            List<XmlReferenceResult> refs = referenceResults(sig.getSignedInfo());
            String detail = valid ? null : Messages.get(MsgKey.XML_SIGNATURE_INVALID);
            trace.v(label + ": " + (valid
                ? Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_OK)
                : Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_MISMATCH)));
            return new XmlIntegrityResult(valid ? IntegrityOutcome.VALID : IntegrityOutcome.INVALID, refs, detail);
        } catch (MissingResourceFailureException e) {
            Reference ref = e.getReference();
            String uri = ref != null && ref.getURI() != null ? ref.getURI() : "";
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_ERROR,
                Messages.get(MsgKey.XML_DETACHED_NO_DOCUMENT, uri)));
            return new XmlIntegrityResult(IntegrityOutcome.UNRESOLVABLE, List.of(), uri);
        } catch (XMLSecurityException e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_ERROR, e.getMessage()));
            return new XmlIntegrityResult(IntegrityOutcome.INVALID, List.of(), e.getMessage());
        }
    }

    private static final class ExternalDocumentResolver extends ResourceResolverSpi {
        private final DocumentSource document;

        ExternalDocumentResolver(DocumentSource document) {
            this.document = document;
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context) {
            String uri = context.uriToResolve;
            return uri != null && !uri.isEmpty() && !uri.startsWith("#");
        }

        @Override
        public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
            try {
                return new XMLSignatureInput(document.open());
            } catch (IOException e) {
                throw new ResourceResolverException(e, context.uriToResolve, context.baseUri,
                    Messages.get(MsgKey.CONTAINER_DOCUMENT_READ_FAILED, e.getMessage()));
            }
        }
    }

    static XmlIntegrityResult verifyEsfIntegrity(EsfInvoice invoice) {
        return verifyEsfIntegrity(invoice, Trace.NONE, "");
    }

    static XmlIntegrityResult verifyEsfIntegrity(EsfInvoice invoice, Trace trace, String label) {
        ensureInitialized();
        if (invoice.certificateRaw() == null) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_ERROR,
                Messages.get(MsgKey.XML_NO_CERTIFICATE)));
            return new XmlIntegrityResult(IntegrityOutcome.INVALID, List.of(), null);
        }
        try {
            Signature sig = Signature.getInstance(ESF_SIGNATURE_ALGORITHM, ActiveBackend.current().jceProviderName());
            sig.initVerify(invoice.certificateRaw().getPublicKey());
            sig.update(invoice.signedBytes());
            boolean valid = sig.verify(invoice.signatureValue());
            trace.v(label + ": " + (valid
                ? Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_OK)
                : Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_MISMATCH)));
            return new XmlIntegrityResult(valid ? IntegrityOutcome.VALID : IntegrityOutcome.INVALID, List.of(), null);
        } catch (GeneralSecurityException e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_INTEGRITY_ERROR, e.getMessage()));
            return new XmlIntegrityResult(IntegrityOutcome.INVALID, List.of(), e.getMessage());
        }
    }

    private static List<XmlReferenceResult> referenceResults(SignedInfo signedInfo) {
        List<XmlReferenceResult> refs = new ArrayList<>(signedInfo.getLength());
        for (int i = 0; i < signedInfo.getLength(); i++) {
            try {
                Reference ref = signedInfo.item(i);
                refs.add(new XmlReferenceResult(ref.getURI(), ref.verify(), null));
            } catch (XMLSecurityException e) {
                refs.add(new XmlReferenceResult(null, false, e.getMessage()));
            }
        }
        return refs;
    }

    static List<SigningCertMatchResult> verifySigningCertificateV2(
            List<SigningCertDigest> entries, X509Certificate signerCert) {
        return verifySigningCertificateV2(entries, signerCert, Trace.NONE, "");
    }

    static List<SigningCertMatchResult> verifySigningCertificateV2(
            List<SigningCertDigest> entries, X509Certificate signerCert, Trace trace, String label) {
        ensureInitialized();
        List<SigningCertMatchResult> results = new ArrayList<>(entries.size());
        byte[] certDer;
        try {
            certDer = signerCert == null ? null : signerCert.getEncoded();
        } catch (CertificateEncodingException e) {
            certDer = null;
        }
        for (SigningCertDigest entry : entries) {
            results.add(matchOne(entry, certDer, trace, label));
        }
        return results;
    }

    private static SigningCertMatchResult matchOne(
            SigningCertDigest entry, byte[] certDer, Trace trace, String label) {
        String jceName = entry.digestAlgorithm() == null ? null
            : JCEMapper.translateURItoJCEID(entry.digestAlgorithm());
        if (jceName == null) {
            trace.v(label + ": " + Messages.get(
                MsgKey.XML_TRACE_SIGNING_CERT_V2_UNKNOWN_ALG, entry.digestAlgorithm()));
            return new SigningCertMatchResult(entry.digestAlgorithm(), false,
                Messages.get(MsgKey.XML_SIGNING_CERT_DIGEST_ALGORITHM_UNKNOWN, entry.digestAlgorithm()));
        }
        if (certDer == null || entry.digestValue() == null) {
            trace.v(label + ": " + Messages.get(MsgKey.XML_TRACE_SIGNING_CERT_V2_MISMATCH, jceName));
            return new SigningCertMatchResult(entry.digestAlgorithm(), false,
                Messages.get(MsgKey.XML_SIGNING_CERT_MISMATCH));
        }
        try {
            MessageDigest md = MessageDigest.getInstance(jceName, ActiveBackend.current().jceProviderName());
            byte[] actual = md.digest(certDer);
            boolean matched = Arrays.equals(actual, entry.digestValue());
            trace.v(label + ": " + Messages.get(
                matched ? MsgKey.XML_TRACE_SIGNING_CERT_V2_MATCH : MsgKey.XML_TRACE_SIGNING_CERT_V2_MISMATCH, jceName));
            return new SigningCertMatchResult(entry.digestAlgorithm(), matched,
                matched ? null : Messages.get(MsgKey.XML_SIGNING_CERT_MISMATCH));
        } catch (GeneralSecurityException e) {
            trace.v(label + ": " + Messages.get(MsgKey.XML_TRACE_SIGNING_CERT_V2_ERROR, rootMessage(e)));
            return new SigningCertMatchResult(entry.digestAlgorithm(), false, e.getMessage());
        }
    }

    static String traceAndResolveAuthority(
            X509Certificate signerCert, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, boolean ignoreTruststore, Trace trace, String label) {
        AnchorInfo anchor = resolveAnchor(signerCert, containerCerts, trust, ignoreTruststore);
        String anchorTrace;
        if (anchor.anchored()) {
            anchorTrace = anchor.caCert() != null
                ? Messages.get(MsgKey.PROVIDER_TRACE_ANCHOR_BOUND_WITH_CA,
                    anchor.caCert().getSubjectX500Principal().getName())
                : Messages.get(MsgKey.PROVIDER_TRACE_ANCHOR_BOUND);
        } else {
            anchorTrace = Messages.get(MsgKey.PROVIDER_TRACE_ANCHOR_NOT_BOUND, anchor.detail());
        }
        trace.v(label + ": " + anchorTrace);
        if (anchor.caCert() != null) {
            return Authorities.detect(anchor.caCert());
        }
        if (ignoreTruststore) {
            return Authorities.detectPrincipal(anchor.signerIssuerName());
        }
        return null;
    }

    static StageOutcome verifyChain(
            X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore,
            List<SigningCertDigest> signingCertificateV2) {
        return verifyChain(target, containerCerts, trust, refTime, ignoreTruststore, signingCertificateV2,
            List.of(), List.of(), null, Map.of(), Trace.NONE, "").outcome();
    }

    static XmlChainResult verifyChain(
            X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore,
            List<SigningCertDigest> signingCertificateV2, List<byte[]> ocspValues, List<byte[]> crlValues,
            String crlPath, Map<String, byte[]> externalOcsp, Trace trace, String label) {
        if (!signingCertificateV2.isEmpty()) {
            SigningCertMatchResult scv2 =
                verifySigningCertificateV2(List.of(signingCertificateV2.get(0)), target, trace, label).get(0);
            if (!scv2.matched()) {
                return new XmlChainResult(new StageOutcome(CheckStatus.FAIL, scv2.errorDetail() != null
                    ? scv2.errorDetail() : Messages.get(MsgKey.XML_SIGNING_CERT_MISMATCH)), List.of());
            }
        }
        try {
            List<X509Certificate> path = buildPath(target, containerCerts, trust, refTime, ignoreTruststore);
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_BUILT));
            kz.edscheck.provider.jce.JceVerificationProvider kp = new kz.edscheck.provider.jce.JceVerificationProvider(trace);
            List<CaRevocationFact> facts = kp.intermediateCaRevocationsForBag(
                path, ocspValues, crlValues, containerCerts, trust, refTime, crlPath, ignoreTruststore,
                label, externalOcsp);
            return new XmlChainResult(new StageOutcome(CheckStatus.PASS), facts);
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_NOT_BUILT, rootMessage(e)));
            return new XmlChainResult(new StageOutcome(CheckStatus.FAIL, rootMessage(e)), List.of());
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

    private static final DateTimeFormatter TRACE_DT_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx", Locale.ROOT);

    private static String traceDt(Instant value) {
        return value == null ? "null" : value.atZone(ZoneId.systemDefault()).format(TRACE_DT_FMT);
    }

    static void registerIds(Document doc) {
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element el = (Element) all.item(i);
            String id = el.getAttribute("Id");
            if (!id.isEmpty()) {
                el.setIdAttribute("Id", true);
            }
        }
    }
}
