package kz.edscheck.xml;

import static kz.edscheck.provider.kalkan.KalkanProvider.buildPath;
import static kz.edscheck.provider.kalkan.KalkanProvider.crlSignOk;
import static kz.edscheck.provider.kalkan.KalkanProvider.findBySubject;
import static kz.edscheck.provider.kalkan.KalkanProvider.hasOcspSigning;
import static kz.edscheck.provider.kalkan.KalkanProvider.reasonLabel;
import static kz.edscheck.provider.kalkan.KalkanProvider.resolveAnchor;
import static kz.edscheck.provider.kalkan.KalkanProvider.toInstant;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CRLReason;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

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
import kz.edscheck.domain.RevocationSource;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.TimestampInfo;
import kz.edscheck.provider.kalkan.KalkanProvider.AnchorInfo;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.Authorities;
import kz.edscheck.trust.DigestAlgorithms;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import kz.gov.pki.kalkan.ocsp.RevokedStatus;
import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.gov.pki.kalkan.ocsp.SingleResp;

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
        if (Security.getProvider("KALKAN") == null) {
            Security.addProvider(new KalkanProvider());
        }

        Init.init();
        JCEMapper.setProviderId("KALKAN");
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
        return verifyTimestamp(
            ps, signatureElement, containerCerts, trust, refTime, ignoreTruststore, Trace.NONE, "");
    }

    static TimestampInfo verifyTimestamp(
            ParsedXmlSignature ps, Element signatureElement, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore, Trace trace, String label) {
        if (ps.signatureTimestampToken() == null) {
            return TimestampInfo.absent();
        }
        ensureInitialized();
        try {
            ASN1InputStream ain = new ASN1InputStream(ps.signatureTimestampToken());
            ContentInfo ci = ContentInfo.getInstance(ain.readObject());
            CMSSignedData tstCms = new CMSSignedData(ci);
            SignerInformation tstSi = (SignerInformation) tstCms.getSignerInfos().getSigners().iterator().next();
            TimeStampToken tst = new TimeStampToken(ci);
            Instant genTime = tst.getTimeStampInfo().getGenTime() == null ? null
                : tst.getTimeStampInfo().getGenTime().toInstant();

            CertStore certStore = tstCms.getCertificatesAndCRLs("Collection", "KALKAN");
            @SuppressWarnings("unchecked")
            Collection<? extends java.security.cert.Certificate> tsaCertColl =
                (Collection<? extends java.security.cert.Certificate>) certStore.getCertificates(tstSi.getSID());
            X509Certificate tsaCert = tsaCertColl.isEmpty() ? null : (X509Certificate) tsaCertColl.iterator().next();
            List<X509Certificate> tsaCerts = new ArrayList<>();
            for (java.security.cert.Certificate c : certStore.getCertificates(null)) {
                tsaCerts.add((X509Certificate) c);
            }
            String tsaCertName = tsaCert == null ? "?" : tsaCert.getSubjectX500Principal().getName();

            Boolean sigOk;
            try {
                sigOk = tsaCert != null && tstSi.verify(tsaCert.getPublicKey(), "KALKAN");
            } catch (Exception e) {
                sigOk = false;
            }
            trace.v(label + ": " + (Boolean.TRUE.equals(sigOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TST_SIGNATURE_OK, tsaCertName)
                : Messages.get(MsgKey.PROVIDER_TRACE_TST_SIGNATURE_FAIL, tsaCertName)));

            String jceName = DigestAlgorithms.jceName(tst.getTimeStampInfo().getMessageImprintAlgOID());
            Boolean bindingOk;
            if (jceName == null || ps.signatureTimestampCanonicalizationMethod() == null) {
                bindingOk = false;
            } else {
                byte[] canonSv = canonicalizeSignatureValue(
                    signatureElement, ps.signatureTimestampCanonicalizationMethod());
                MessageDigest md = MessageDigest.getInstance(jceName, "KALKAN");
                byte[] calc = md.digest(canonSv);
                bindingOk = Arrays.equals(calc, tst.getTimeStampInfo().getMessageImprintDigest());
            }
            trace.v(label + ": " + (Boolean.TRUE.equals(bindingOk)
                ? Messages.get(MsgKey.PROVIDER_TRACE_TST_BINDING_OK, jceName)
                : Messages.get(MsgKey.PROVIDER_TRACE_TST_BINDING_FAIL, jceName)));

            Boolean chainOk;
            String chainDetail = null;
            try {
                List<X509Certificate> pool = new ArrayList<>(containerCerts);
                pool.addAll(tsaCerts);
                buildPath(tsaCert, pool, trust, refTime, ignoreTruststore);
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

            String detail = null;
            if (!Boolean.TRUE.equals(sigOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_SIG_FAILED);
            } else if (!Boolean.TRUE.equals(chainOk)) {
                detail = chainDetail;
            } else if (Boolean.FALSE.equals(bindingOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_BINDING_FAILED);
            } else if (Boolean.FALSE.equals(validityOk)) {
                detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_CERT_EXPIRED);
            }

            boolean valid = !Boolean.FALSE.equals(sigOk) && !Boolean.FALSE.equals(bindingOk)
                && !Boolean.FALSE.equals(chainOk) && !Boolean.FALSE.equals(validityOk);

            return new TimestampInfo(true, valid, genTime, detail, null, null);
        } catch (Exception e) {
            String detail = Messages.get(MsgKey.PROVIDER_TIMESTAMP_PARSE_FAILED, e.getMessage());
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_TST_PARSE_FAILED, detail));
            return new TimestampInfo(true, false, null, detail, null, null);
        }
    }

    private static Boolean tsaCertInValidity(X509Certificate tsaCert, Instant genTime) {
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
            Signature sig = Signature.getInstance(ESF_SIGNATURE_ALGORITHM, "KALKAN");
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
            MessageDigest md = MessageDigest.getInstance(jceName, "KALKAN");
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
            Trace.NONE, "");
    }

    static StageOutcome verifyChain(
            X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, Instant refTime, boolean ignoreTruststore,
            List<SigningCertDigest> signingCertificateV2, Trace trace, String label) {
        if (!signingCertificateV2.isEmpty()) {
            SigningCertMatchResult scv2 =
                verifySigningCertificateV2(List.of(signingCertificateV2.get(0)), target, trace, label).get(0);
            if (!scv2.matched()) {
                return new StageOutcome(CheckStatus.FAIL, scv2.errorDetail() != null
                    ? scv2.errorDetail() : Messages.get(MsgKey.XML_SIGNING_CERT_MISMATCH));
            }
        }
        try {
            buildPath(
                target, containerCerts, trust, refTime, ignoreTruststore);
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_BUILT));
            return new StageOutcome(CheckStatus.PASS);
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CHAIN_NOT_BUILT, rootMessage(e)));
            return new StageOutcome(CheckStatus.FAIL, rootMessage(e));
        }
    }

    static StageOutcome verifyEmbeddedOcsp(
            List<byte[]> ocspValues, List<byte[]> crlValues, String crlPath, X509Certificate signerCert,
            List<X509Certificate> trust, List<X509Certificate> containerCerts,
            Instant refTime, boolean ignoreTruststore) {
        return verifyEmbeddedOcsp(ocspValues, crlValues, crlPath, signerCert, trust, containerCerts,
            refTime, ignoreTruststore, Trace.NONE, "");
    }

    static StageOutcome verifyEmbeddedOcsp(
            List<byte[]> ocspValues, List<byte[]> crlValues, String crlPath, X509Certificate signerCert,
            List<X509Certificate> trust, List<X509Certificate> containerCerts,
            Instant refTime, boolean ignoreTruststore, Trace trace, String label) {
        ensureInitialized();
        if (!ocspValues.isEmpty()) {
            for (byte[] der : ocspValues) {
                StageOutcome outcome =
                    tryOneOcsp(der, signerCert, trust, containerCerts, refTime, ignoreTruststore, trace, label);
                if (outcome != null) {
                    return outcome;
                }
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_CERTID_MISMATCH));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_CERTID_MISMATCH));
        }
        if (!crlValues.isEmpty()) {
            X509CRL embedded = extractEmbeddedCrlForSigner(crlValues, signerCert, trace, label);
            if (embedded != null) {
                return verifyCrlObject(embedded, signerCert, trust, containerCerts, refTime, ignoreTruststore,
                    RevocationSource.CRL_EMBEDDED, trace, label, Messages.get(MsgKey.PROVIDER_CRL_EMBEDDED_LABEL));
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_EMBEDDED_NO_MATCH));
            return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_EMBEDDED)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_MISMATCH)).build();
        }
        if (crlPath == null) {
            String noOcspNoCrl = Messages.get(MsgKey.PROVIDER_REVOCATION_NO_OCSP_NO_CRL);
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_REVOCATION_PREFIX, noOcspNoCrl));
            return new StageOutcome(CheckStatus.NOT_VERIFIED, noOcspNoCrl);
        }
        return verifyCrl(crlPath, signerCert, trust, containerCerts, refTime, ignoreTruststore, trace, label);
    }

    private static StageOutcome verifyCrl(
            String crlPath, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore,
            Trace trace, String label) {
        X509CRL crl;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "KALKAN");
            try (InputStream in = new FileInputStream(crlPath)) {
                crl = (X509CRL) cf.generateCRL(in);
            }
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_PARSE_FAILED, crlPath, rootMessage(e)));
            return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.CRL_FILE)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_PARSE_FAILED, rootMessage(e))).build();
        }
        return verifyCrlObject(crl, signerCert, trust, containerCerts, refTime, ignoreTruststore,
            RevocationSource.CRL_FILE, trace, label, crlPath);
    }

    private static StageOutcome verifyCrlObject(
            X509CRL crl, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore,
            RevocationSource source, Trace trace, String label, String crlLabel) {
        try {
            if (!crl.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal())) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_MISMATCH, crlLabel));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_MISMATCH)).build();
            }
            X509Certificate issuer = findBySubject(crl.getIssuerX500Principal(), trust, containerCerts);
            if (issuer == null) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_NOT_FOUND, crlLabel));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_NOT_FOUND)).build();
            }
            try {
                crl.verify(issuer.getPublicKey(), "KALKAN");
            } catch (Exception e) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_SIGNATURE_FAILED,
                    crlLabel, rootMessage(e)));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_SIGNATURE_FAILED, rootMessage(e))).build();
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_SIGNATURE_OK, crlLabel));
            if (!crlSignOk(issuer)) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_NO_CRL_SIGN, crlLabel));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_NO_CRL_SIGN)).build();
            }
            try {
                buildPath(issuer, containerCerts, trust, refTime, ignoreTruststore);
            } catch (Exception e) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_CHAIN_FAILED,
                    crlLabel, rootMessage(e)));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_CHAIN_FAILED, rootMessage(e))).build();
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_ISSUER_CHAIN_OK, crlLabel));
            Instant thisUpdate = toInstant(crl.getThisUpdate());
            Instant nextUpdate = toInstant(crl.getNextUpdate());
            X509CRLEntry entry = crl.getRevokedCertificate(signerCert);
            if (entry != null) {
                CRLReason r = entry.getRevocationReason();
                String reason = r != null ? reasonLabel(r.ordinal()) : null;
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_REVOKED, reason));
                return StageOutcome.of(CheckStatus.FAIL).source(source)
                    .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_REVOKED))
                    .validFrom(thisUpdate).validUntil(nextUpdate)
                    .revokedAt(toInstant(entry.getRevocationDate())).revokedReason(reason).build();
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_NOT_REVOKED,
                traceDt(thisUpdate), traceDt(nextUpdate)));
            return StageOutcome.of(CheckStatus.PASS).source(source)
                .validFrom(thisUpdate).validUntil(nextUpdate).build();
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_PARSE_FAILED, crlLabel, rootMessage(e)));
            return StageOutcome.of(CheckStatus.FAIL).source(source)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_PARSE_FAILED, rootMessage(e))).build();
        }
    }

    static X509CRL extractEmbeddedCrlForSigner(
            List<byte[]> crlValues, X509Certificate signerCert, Trace trace, String label) {
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509", "KALKAN");
        } catch (Exception e) {
            return null;
        }
        int index = 0;
        for (byte[] der : crlValues) {
            index++;
            X509CRL crl;
            try {
                crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(der));
            } catch (Exception parseEx) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_EMBEDDED_SKIPPED,
                    index, rootMessage(parseEx)));
                continue;
            }
            if (crl != null && crl.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal())) {
                return crl;
            }
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_CRL_EMBEDDED_SKIPPED,
                index, Messages.get(MsgKey.PROVIDER_REVOCATION_CRL_ISSUER_MISMATCH)));
        }
        return null;
    }

    private static StageOutcome tryOneOcsp(
            byte[] der, X509Certificate signerCert, List<X509Certificate> trust,
            List<X509Certificate> containerCerts, Instant refTime, boolean ignoreTruststore,
            Trace trace, String label) {
        BasicOCSPResp basic;
        X509Certificate issuerCert =
            findBySubject(
                signerCert.getIssuerX500Principal(), trust, containerCerts);
        try {
            OCSPResp resp = new OCSPResp(der);
            Object obj = resp.getResponseObject();
            if (!(obj instanceof BasicOCSPResp)) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_NOT_EXTRACTED));
                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_NOT_EXTRACTED));
            }
            basic = (BasicOCSPResp) obj;
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
        }

        SingleResp match = null;
        try {
            if (issuerCert != null) {
                for (SingleResp sr : basic.getResponses()) {
                    CertificateID respId = sr.getCertID();
                    try {
                        CertificateID expectedId =
                            new CertificateID(respId.getHashAlgOID(), issuerCert, signerCert.getSerialNumber(), "KALKAN");
                        if (expectedId.equals(respId)) {
                            match = sr;
                            break;
                        }
                    } catch (Exception ignored) {

                    }
                }
            }
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
        }
        if (match == null) {
            return null; 
        }

        X509Certificate[] respCerts;
        try {
            respCerts = basic.getCerts("KALKAN");
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
        }
        X509Certificate responder = (respCerts != null && respCerts.length > 0) ? respCerts[0] : null;
        if (responder == null) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_MISSING));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_RESPONDER_MISSING));
        }
        try {
            if (!basic.verify(responder.getPublicKey(), "KALKAN")) {
                trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_SIGNATURE_FAILED));
                return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_SIGNATURE_FAILED));
            }
        } catch (Exception e) {
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_PARSE_FAILED, e.getMessage()));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_PARSE_FAILED, e.getMessage()));
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
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_CHAIN_FAILED, rootMessage(e)));
            return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_CHAIN_PREFIX, rootMessage(e)));
        }
        trace.v(label + ": " + Messages.get(
            MsgKey.PROVIDER_TRACE_OCSP_RESPONDER_AUTHORIZED, responder.getSubjectX500Principal().getName()));

        trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_CERTID_MATCH));

        Object status = match.getCertStatus();
        Instant thisUpdate = toInstant(match.getThisUpdate());
        Instant nextUpdate = toInstant(match.getNextUpdate());
        if (status == null) {
            trace.v(label + ": " + Messages.get(
                MsgKey.PROVIDER_TRACE_OCSP_STATUS_GOOD, traceDt(thisUpdate), traceDt(nextUpdate)));
            return StageOutcome.of(CheckStatus.PASS).source(RevocationSource.OCSP)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_GOOD))
                .validFrom(thisUpdate).validUntil(nextUpdate).build();
        }
        if (status instanceof RevokedStatus rs) {
            Instant revokedAt = toInstant(rs.getRevocationTime());
            String reason = rs.hasRevocationReason()
                ? reasonLabel(rs.getRevocationReason()) : null;
            trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_REVOKED, traceDt(revokedAt), reason));
            return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.OCSP)
                .detail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_REVOKED))
                .validFrom(thisUpdate).validUntil(nextUpdate)
                .revokedAt(revokedAt).revokedReason(reason).build();
        }
        trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_OCSP_STATUS_UNKNOWN));
        return revFail(Messages.get(MsgKey.PROVIDER_REVOCATION_OCSP_STATUS_UNKNOWN));
    }

    private static StageOutcome revFail(String detail) {
        return StageOutcome.of(CheckStatus.FAIL).source(RevocationSource.OCSP).detail(detail).build();
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

    private static void registerIds(Document doc) {
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
