package kz.edscheck.xml;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.ArchiveMarkOutcome;
import kz.edscheck.provider.ArchiveTimestampInfo;
import kz.edscheck.provider.CaRevocationFact;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.kalkan.KalkanProvider;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.DigestAlgorithms;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

final class XmlArchiveTimestamp {
    private static final Base64.Decoder BASE64 = Base64.getMimeDecoder();
    private static final String OID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";

    private XmlArchiveTimestamp() {
    }

    record Result(ArchiveTimestampInfo info, List<ArchiveMarkOutcome> markOutcomes) {
        static Result none() {
            return new Result(ArchiveTimestampInfo.none(), List.of());
        }
    }

    static Result check(
            Document doc, Element signatureElement, Element qualifyingProperties, boolean detached,
            List<byte[]> baseOcspValues, List<byte[]> baseCrlValues, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, boolean ignoreTruststore, String crlPath, Map<String, byte[]> externalOcsp,
            Trace trace, String label) {
        if (qualifyingProperties == null) {
            return Result.none();
        }
        Element unsignedProperties =
            XmlSignatureParser.firstChildByTagNS(qualifyingProperties, XmlNamespaces.XADES_132, "UnsignedProperties");
        Element unsignedSignatureProperties = unsignedProperties == null ? null
            : XmlSignatureParser.firstChildByTagNS(unsignedProperties, XmlNamespaces.XADES_132, "UnsignedSignatureProperties");
        List<Element> markNodes = archiveMarkNodes(unsignedSignatureProperties);
        if (markNodes.isEmpty()) {
            return Result.none();
        }

        XmlCrypto.ensureInitialized();
        XmlCrypto.registerIds(doc);
        List<ArchiveMarkOutcome> outcomes = new ArrayList<>(markNodes.size());
        for (int position = 0; position < markNodes.size(); position++) {
            outcomes.add(checkOne(position, markNodes.get(position), unsignedSignatureProperties, signatureElement,
                detached, baseOcspValues, baseCrlValues, containerCerts, trust, ignoreTruststore, crlPath,
                externalOcsp, trace, label));
        }
        Instant lastGenTime = outcomes.get(outcomes.size() - 1).genTime();
        return new Result(new ArchiveTimestampInfo(markNodes.size(), 0, lastGenTime), outcomes);
    }

    private static List<Element> archiveMarkNodes(Element unsignedSignatureProperties) {
        if (unsignedSignatureProperties == null) {
            return List.of();
        }
        List<Element> result = new ArrayList<>();
        NodeList children = unsignedSignatureProperties.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && "ArchiveTimeStamp".equals(n.getLocalName())
                    && XmlNamespaces.XADES_141.equals(n.getNamespaceURI())) {
                result.add((Element) n);
            }
        }
        return result;
    }

    private static ArchiveMarkOutcome checkOne(
            int position, Element markNode, Element unsignedSignatureProperties, Element signatureElement,
            boolean detached, List<byte[]> baseOcspValues, List<byte[]> baseCrlValues,
            List<X509Certificate> containerCerts, List<X509Certificate> trust, boolean ignoreTruststore,
            String crlPath, Map<String, byte[]> externalOcsp, Trace trace, String label) {

        TokenParse parsed;
        try {
            parsed = parseToken(markNode);
        } catch (Exception e) {
            return parseFailed(position, null, Messages.get(MsgKey.ARCHIVE_TS_TST_PARSE_FAILED, String.valueOf(e.getMessage())));
        }
        SignerInformation tstSi = parsed.tstSi();
        X509Certificate tsaCert = parsed.tsaCert();
        List<X509Certificate> tsaCerts = parsed.tsaCerts();
        Instant genTime = parsed.genTime();
        String imprintAlgOid = parsed.imprintAlgOid();
        byte[] recordedImprint = parsed.recordedImprint();

        String canonicalizationMethod = canonicalizationMethodOf(markNode);
        if (canonicalizationMethod == null || !XmlAlgorithms.CANONICALIZATION.contains(canonicalizationMethod)) {
            return parseFailed(position, genTime, Messages.get(MsgKey.XML_CANONICALIZATION_NOT_SUPPORTED,
                canonicalizationMethod == null ? "(отсутствует)" : canonicalizationMethod));
        }
        if (detached) {
            return parseFailed(position, genTime, Messages.get(MsgKey.ARCHIVE_TS_XML_DETACHED_NOT_SUPPORTED));
        }

        byte[] imprintBlob;
        try {
            imprintBlob = imprintBlob(markNode, unsignedSignatureProperties, signatureElement, canonicalizationMethod);
        } catch (Exception e) {
            return parseFailed(position, genTime, Messages.get(MsgKey.ARCHIVE_TS_TST_PARSE_FAILED, String.valueOf(e.getMessage())));
        }

        Boolean sigOk;
        try {
            sigOk = tsaCert != null && tstSi.verify(tsaCert.getPublicKey(), "KALKAN");
        } catch (Exception e) {
            sigOk = false;
        }

        Boolean chainOk;
        List<X509Certificate> markPath = List.of();
        List<X509Certificate> pool = new ArrayList<>(containerCerts);
        pool.addAll(tsaCerts);
        try {
            markPath = KalkanProvider.buildPath(tsaCert, pool, trust, genTime, ignoreTruststore);
            chainOk = true;
        } catch (Exception e) {
            chainOk = false;
        }

        Boolean tsaValidityOk = XmlCrypto.tsaCertInValidity(tsaCert, genTime);
        Boolean tsaEkuOk = tsaEkuOk(tsaCert);

        StageOutcome ownRevocation = null;
        Instant tsaCertNotAfter = null;
        List<CaRevocationFact> caFacts = List.of();
        if (Boolean.TRUE.equals(chainOk)) {
            tsaCertNotAfter = tsaCert.getNotAfter().toInstant();
            Element validationData = timeStampValidationDataFor(markNode, unsignedSignatureProperties);
            List<byte[]> ocspBag = combined(validationData, baseOcspValues, "OCSPValues", "EncapsulatedOCSPValue");
            List<byte[]> crlBag = combined(validationData, baseCrlValues, "CRLValues", "EncapsulatedCRLValue");
            String markLabel = label + Messages.get(MsgKey.PROVIDER_LABEL_ARCHIVE_MARK_SUFFIX, position + 1);
            KalkanProvider kp = new KalkanProvider(trace);
            ownRevocation = kp.revocationCascadeForBag(tsaCert, ocspBag, crlBag, pool, trust, genTime, crlPath,
                ignoreTruststore, externalOcsp, markLabel + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX));
            caFacts = kp.intermediateCaRevocationsForBag(markPath, ocspBag, crlBag, pool, trust, genTime, crlPath,
                ignoreTruststore, markLabel, externalOcsp);
        }

        String hashFailure = imprintFailure(imprintAlgOid, imprintBlob, recordedImprint);

        String cryptoSummary = kz.edscheck.parsing.ArchiveTs.markFailure(
            null, sigOk, chainOk, chainOk, tsaValidityOk, tsaEkuOk, null, hashFailure);
        trace.v(label + ": " + Messages.get(MsgKey.PROVIDER_TRACE_ARCHIVE_MARK, position + 1,
            cryptoSummary == null ? Messages.get(MsgKey.PROVIDER_TRACE_ARCHIVE_MARK_OK) : cryptoSummary));

        return new ArchiveMarkOutcome(position, null, genTime, sigOk, chainOk, tsaValidityOk, tsaEkuOk,
            hashFailure, ownRevocation, tsaCertNotAfter, caFacts);
    }

    private static ArchiveMarkOutcome parseFailed(int position, Instant genTime, String parseError) {
        return new ArchiveMarkOutcome(position, parseError, genTime, null, null, null, null, null, null, null, List.of());
    }

    private record TokenParse(
            SignerInformation tstSi, X509Certificate tsaCert, List<X509Certificate> tsaCerts, Instant genTime,
            String imprintAlgOid, byte[] recordedImprint) {
    }

    private static TokenParse parseToken(Element markNode) throws Exception {
        Element encapsulated =
            XmlSignatureParser.firstChildByTagNS(markNode, XmlNamespaces.XADES_132, "EncapsulatedTimeStamp");
        String text = encapsulated == null ? null : encapsulated.getTextContent();
        if (text == null || text.isBlank()) {
            throw new IllegalStateException("EncapsulatedTimeStamp");
        }
        byte[] tokenDer = BASE64.decode(text.trim());
        ASN1InputStream ain = new ASN1InputStream(tokenDer);
        ContentInfo ci = ContentInfo.getInstance(ain.readObject());
        CMSSignedData tstCms = new CMSSignedData(ci);
        SignerInformation tstSi = (SignerInformation) tstCms.getSignerInfos().getSigners().iterator().next();
        TimeStampToken tst = new TimeStampToken(ci);
        Instant genTime = tst.getTimeStampInfo().getGenTime() == null ? null
            : tst.getTimeStampInfo().getGenTime().toInstant();
        String imprintAlgOid = tst.getTimeStampInfo().getMessageImprintAlgOID();
        byte[] recordedImprint = tst.getTimeStampInfo().getMessageImprintDigest();

        CertStore certStore = tstCms.getCertificatesAndCRLs("Collection", "KALKAN");
        @SuppressWarnings("unchecked")
        Collection<? extends java.security.cert.Certificate> tsaCertColl =
            (Collection<? extends java.security.cert.Certificate>) certStore.getCertificates(tstSi.getSID());
        X509Certificate tsaCert = tsaCertColl.isEmpty() ? null : (X509Certificate) tsaCertColl.iterator().next();
        List<X509Certificate> tsaCerts = new ArrayList<>();
        for (java.security.cert.Certificate c : certStore.getCertificates(null)) {
            tsaCerts.add((X509Certificate) c);
        }
        return new TokenParse(tstSi, tsaCert, tsaCerts, genTime, imprintAlgOid, recordedImprint);
    }

    record MarkTarget(
            int position, X509Certificate tsaCert, List<X509Certificate> tsaCerts, Instant genTime,
            List<byte[]> ocspBag, List<byte[]> crlBag) {
    }

    static List<MarkTarget> peekMarkTargets(
            Element qualifyingProperties, List<byte[]> baseOcspValues, List<byte[]> baseCrlValues) {
        if (qualifyingProperties == null) {
            return List.of();
        }
        Element unsignedProperties =
            XmlSignatureParser.firstChildByTagNS(qualifyingProperties, XmlNamespaces.XADES_132, "UnsignedProperties");
        Element unsignedSignatureProperties = unsignedProperties == null ? null
            : XmlSignatureParser.firstChildByTagNS(unsignedProperties, XmlNamespaces.XADES_132, "UnsignedSignatureProperties");
        List<Element> markNodes = archiveMarkNodes(unsignedSignatureProperties);
        if (markNodes.isEmpty()) {
            return List.of();
        }
        List<MarkTarget> result = new ArrayList<>();
        for (int position = 0; position < markNodes.size(); position++) {
            Element markNode = markNodes.get(position);
            TokenParse parsed;
            try {
                parsed = parseToken(markNode);
            } catch (Exception e) {
                continue;
            }
            if (parsed.tsaCert() == null) {
                continue;
            }
            Element validationData = timeStampValidationDataFor(markNode, unsignedSignatureProperties);
            List<byte[]> ocspBag = combined(validationData, baseOcspValues, "OCSPValues", "EncapsulatedOCSPValue");
            List<byte[]> crlBag = combined(validationData, baseCrlValues, "CRLValues", "EncapsulatedCRLValue");
            result.add(new MarkTarget(position, parsed.tsaCert(), parsed.tsaCerts(), parsed.genTime(), ocspBag, crlBag));
        }
        return result;
    }

    private static Boolean tsaEkuOk(X509Certificate tsaCert) {
        if (tsaCert == null) {
            return null;
        }
        try {
            List<String> eku = tsaCert.getExtendedKeyUsage();
            return eku != null && eku.contains(OID_KP_TIME_STAMPING);
        } catch (CertificateParsingException e) {
            return null;
        }
    }

    private static String imprintFailure(String imprintAlgOid, byte[] imprintBlob, byte[] recordedImprint) {
        byte[] computed = null;
        String jceName = imprintAlgOid == null ? null : DigestAlgorithms.jceName(imprintAlgOid);
        if (jceName != null) {
            try {
                computed = MessageDigest.getInstance(jceName, "KALKAN").digest(imprintBlob);
            } catch (Exception e) {
                computed = null;
            }
        }
        if (computed == null || recordedImprint == null) {
            return Messages.get(MsgKey.ARCHIVE_TS_XML_IMPRINT_NOT_RECOMPUTED);
        }
        if (!Arrays.equals(computed, recordedImprint)) {
            return Messages.get(MsgKey.ARCHIVE_TS_XML_IMPRINT_MISMATCH);
        }
        return null;
    }

    private static byte[] imprintBlob(
            Element markNode, Element unsignedSignatureProperties, Element signatureElement,
            String canonicalizationMethod) throws Exception {
        ByteArrayOutputStream blob = new ByteArrayOutputStream();

        XMLSignature sig = new XMLSignature(signatureElement, "");
        SignedInfo signedInfo = sig.getSignedInfo();
        for (int i = 0; i < signedInfo.getLength(); i++) {
            Reference ref = signedInfo.item(i);
            blob.write(ref.getReferencedBytes());
        }

        Element signedInfoEl =
            XmlSignatureParser.firstChildByTagNS(signatureElement, XmlNamespaces.XMLDSIG, "SignedInfo");
        Element signatureValueEl =
            XmlSignatureParser.firstChildByTagNS(signatureElement, XmlNamespaces.XMLDSIG, "SignatureValue");
        Element keyInfoEl =
            XmlSignatureParser.firstChildByTagNS(signatureElement, XmlNamespaces.XMLDSIG, "KeyInfo");
        if (signedInfoEl == null || signatureValueEl == null) {
            throw new IllegalStateException("SignedInfo/SignatureValue");
        }
        blob.write(canonicalizeNode(signedInfoEl, canonicalizationMethod));
        blob.write(canonicalizeNode(signatureValueEl, canonicalizationMethod));
        if (keyInfoEl != null) {
            blob.write(canonicalizeNode(keyInfoEl, canonicalizationMethod));
        }

        if (unsignedSignatureProperties != null) {
            NodeList children = unsignedSignatureProperties.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node n = children.item(i);
                if (n == markNode) {
                    break;
                }
                if (n.getNodeType() == Node.ELEMENT_NODE) {
                    blob.write(canonicalizeNode((Element) n, canonicalizationMethod));
                }
            }
        }

        NodeList objects = signatureElement.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Object");
        for (int i = 0; i < objects.getLength(); i++) {
            Element object = (Element) objects.item(i);
            if (object.getParentNode() != signatureElement || containsQualifyingProperties(object)) {
                continue;
            }
            blob.write(canonicalizeNode(object, canonicalizationMethod));
        }

        return blob.toByteArray();
    }

    private static boolean containsQualifyingProperties(Element object) {
        return object.getElementsByTagNameNS(XmlNamespaces.XADES_132, "QualifyingProperties").getLength() > 0;
    }

    private static byte[] canonicalizeNode(Element node, String algorithmUri) throws Exception {
        Canonicalizer c14n = Canonicalizer.getInstance(algorithmUri);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        c14n.canonicalizeSubtree(node, baos);
        return baos.toByteArray();
    }

    private static String canonicalizationMethodOf(Element markNode) {
        Element cm = XmlSignatureParser.firstChildByTagNS(markNode, XmlNamespaces.XMLDSIG, "CanonicalizationMethod");
        if (cm == null) {
            return null;
        }
        String alg = cm.getAttribute("Algorithm");
        return alg.isEmpty() ? null : alg;
    }

    private static Element timeStampValidationDataFor(Element markNode, Element unsignedSignatureProperties) {
        if (unsignedSignatureProperties == null) {
            return null;
        }
        List<Element> elementChildren = new ArrayList<>();
        List<Element> candidates = new ArrayList<>();
        NodeList children = unsignedSignatureProperties.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element el = (Element) n;
            elementChildren.add(el);
            if ("TimeStampValidationData".equals(el.getLocalName())
                    && XmlNamespaces.XADES_141.equals(el.getNamespaceURI())) {
                candidates.add(el);
            }
        }
        String markId = markNode.getAttribute("Id");
        if (!markId.isEmpty()) {
            String wantedUri = "#" + markId;
            for (Element c : candidates) {
                if (wantedUri.equals(c.getAttribute("URI"))) {
                    return c;
                }
            }
        }
        int markIndex = elementChildren.indexOf(markNode);
        if (markIndex < 0 || markIndex + 1 >= elementChildren.size()) {
            return null;
        }
        Element next = elementChildren.get(markIndex + 1);
        return "TimeStampValidationData".equals(next.getLocalName())
                && XmlNamespaces.XADES_141.equals(next.getNamespaceURI()) ? next : null;
    }

    private static List<byte[]> combined(
            Element validationData, List<byte[]> base, String wrapperLocalName, String entryLocalName) {
        if (validationData == null) {
            return base;
        }
        Element revocationValues =
            XmlSignatureParser.firstChildByTagNS(validationData, XmlNamespaces.XADES_132, "RevocationValues");
        List<byte[]> extra = XmlSignatureParser.encapsulatedValues(revocationValues, wrapperLocalName, entryLocalName);
        if (extra.isEmpty()) {
            return base;
        }
        List<byte[]> result = new ArrayList<>(base);
        result.addAll(extra);
        return result;
    }
}
