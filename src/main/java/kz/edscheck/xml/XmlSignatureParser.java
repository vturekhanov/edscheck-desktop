package kz.edscheck.xml;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import kz.edscheck.domain.Certificate;
import kz.edscheck.parsing.Parsing;

final class XmlSignatureParser {
    private static final Base64.Decoder BASE64 = Base64.getMimeDecoder();

    private XmlSignatureParser() {
    }

    static List<ParsedXmlSignature> parseAll(Document doc) {
        NodeList signatures = doc.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Signature");
        List<ParsedXmlSignature> result = new ArrayList<>(signatures.getLength());
        for (int i = 0; i < signatures.getLength(); i++) {
            result.add(parseOne(doc, (Element) signatures.item(i), i));
        }
        return result;
    }

    private static ParsedXmlSignature parseOne(Document doc, Element signature, int index) {
        String id = signature.getAttribute("Id");
        Element signedInfo = firstChildByTagNS(signature, XmlNamespaces.XMLDSIG, "SignedInfo");
        List<XmlReference> references = signedInfo == null ? List.of() : references(signedInfo);

        Element qualifyingProperties = id.isEmpty() ? null : matchingQualifyingProperties(doc, id);
        boolean referencesSignedProperties = hasSignedPropertiesReference(references);
        boolean xades = qualifyingProperties != null && referencesSignedProperties;
        boolean detached = isDetached(references);

        Element signedProperties = null;
        Element unsignedProperties = null;
        if (qualifyingProperties != null) {
            signedProperties = firstChildByTagNS(qualifyingProperties, XmlNamespaces.XADES_132, "SignedProperties");
            unsignedProperties =
                firstChildByTagNS(qualifyingProperties, XmlNamespaces.XADES_132, "UnsignedProperties");
        }
        Element signedSignatureProperties = signedProperties == null ? null
            : firstChildByTagNS(signedProperties, XmlNamespaces.XADES_132, "SignedSignatureProperties");
        Element unsignedSignatureProperties = unsignedProperties == null ? null
            : firstChildByTagNS(unsignedProperties, XmlNamespaces.XADES_132, "UnsignedSignatureProperties");

        X509Certificate certificateRaw = certificate(signature);
        Certificate certificate = certificateRaw == null ? null : Parsing.certificateFields(certificateRaw);

        Element signatureTimeStamp = unsignedSignatureProperties == null ? null
            : firstChildByTagNS(unsignedSignatureProperties, XmlNamespaces.XADES_132, "SignatureTimeStamp");
        Element revocationValues = unsignedSignatureProperties == null ? null
            : firstChildByTagNS(unsignedSignatureProperties, XmlNamespaces.XADES_132, "RevocationValues");

        return new ParsedXmlSignature(
            index,
            xades,
            detached,
            qualifyingProperties != null,
            signedProperties != null,
            id,
            algorithmAttr(signedInfo, "CanonicalizationMethod"),
            algorithmAttr(signedInfo, "SignatureMethod"),
            references,
            base64OfChild(signature, XmlNamespaces.XMLDSIG, "SignatureValue"),
            certificateRaw,
            certificate,
            signingTime(signedSignatureProperties),
            signingCertificateV2(signedSignatureProperties),
            forbiddenV1Forms(signedSignatureProperties),
            signatureTimeStamp == null ? null : algorithmAttr(signatureTimeStamp, "CanonicalizationMethod"),
            signatureTimeStamp == null ? null
                : base64OfChild(signatureTimeStamp, XmlNamespaces.XADES_132, "EncapsulatedTimeStamp"),
            encapsulatedValues(revocationValues, "OCSPValues", "EncapsulatedOCSPValue"),
            encapsulatedValues(revocationValues, "CRLValues", "EncapsulatedCRLValue"),
            certificateValues(unsignedSignatureProperties));
    }

    static Element matchingQualifyingProperties(Document doc, String signatureId) {
        String wantedTarget = "#" + signatureId;
        NodeList candidates = doc.getElementsByTagNameNS(XmlNamespaces.XADES_132, "QualifyingProperties");
        for (int i = 0; i < candidates.getLength(); i++) {
            Element qp = (Element) candidates.item(i);
            if (wantedTarget.equals(qp.getAttribute("Target"))) {
                return qp;
            }
        }
        return null;
    }

    private static boolean hasSignedPropertiesReference(List<XmlReference> references) {
        for (XmlReference ref : references) {
            if (XmlNamespaces.XADES_SIGNED_PROPERTIES_TYPE.equals(ref.type())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDetached(List<XmlReference> references) {
        for (XmlReference ref : references) {
            if (XmlNamespaces.XADES_SIGNED_PROPERTIES_TYPE.equals(ref.type())) {
                continue;
            }
            if (ref.uri() != null && !ref.uri().isEmpty() && !ref.uri().startsWith("#")) {
                return true;
            }
        }
        return false;
    }

    private static List<XmlReference> references(Element signedInfo) {
        NodeList refs = signedInfo.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Reference");
        List<XmlReference> result = new ArrayList<>(refs.getLength());
        for (int i = 0; i < refs.getLength(); i++) {
            Element ref = (Element) refs.item(i);
            result.add(new XmlReference(
                emptyToNull(ref.getAttribute("Id")),
                ref.getAttribute("URI"),
                emptyToNull(ref.getAttribute("Type")),
                transforms(ref),
                algorithmAttr(ref, "DigestMethod"),
                base64OfChild(ref, XmlNamespaces.XMLDSIG, "DigestValue")));
        }
        return result;
    }

    private static List<String> transforms(Element reference) {
        Element transformsEl = firstChildByTagNS(reference, XmlNamespaces.XMLDSIG, "Transforms");
        if (transformsEl == null) {
            return List.of();
        }
        NodeList nodes = transformsEl.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Transform");
        List<String> result = new ArrayList<>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            result.add(((Element) nodes.item(i)).getAttribute("Algorithm"));
        }
        return result;
    }

    private static X509Certificate certificate(Element signature) {
        Element keyInfo = firstChildByTagNS(signature, XmlNamespaces.XMLDSIG, "KeyInfo");
        if (keyInfo == null) {
            return null;
        }

        NodeList certNodes = keyInfo.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "X509Certificate");
        if (certNodes.getLength() == 0) {
            return null;
        }
        String text = certNodes.item(0).getTextContent();
        if (text == null || text.isBlank()) {
            return null;
        }
        return XmlCertificates.parse(text);
    }

    private static Instant signingTime(Element signedSignatureProperties) {
        String text = signedSignatureProperties == null ? null
            : firstChildTextByTagNS(signedSignatureProperties, XmlNamespaces.XADES_132, "SigningTime");
        if (text == null) {
            return null;
        }
        try {
            return Instant.parse(text.trim());
        } catch (DateTimeParseException e) {
            return null; 
        }
    }

    private static List<SigningCertDigest> signingCertificateV2(Element signedSignatureProperties) {
        if (signedSignatureProperties == null) {
            return List.of();
        }
        Element scv2 = firstChildByTagNS(signedSignatureProperties, XmlNamespaces.XADES_141, "SigningCertificateV2");
        if (scv2 == null) {
            scv2 = firstChildByTagNS(signedSignatureProperties, XmlNamespaces.XADES_132, "SigningCertificateV2");
        }
        if (scv2 == null) {
            return List.of();
        }
        List<SigningCertDigest> result = new ArrayList<>();
        for (Element certEl : childrenByLocalName(scv2, "Cert")) {
            Element certDigest = firstChildByLocalName(certEl, "CertDigest");
            if (certDigest == null) {
                continue;
            }
            String alg = algorithmAttr(certDigest, "DigestMethod");
            byte[] value = base64OfChild(certDigest, XmlNamespaces.XMLDSIG, "DigestValue");
            result.add(new SigningCertDigest(alg, value));
        }
        return result;
    }

    private static List<String> forbiddenV1Forms(Element signedSignatureProperties) {
        if (signedSignatureProperties == null) {
            return List.of();
        }
        List<String> found = new ArrayList<>();
        for (String localName : new String[] {"SigningCertificate", "SignatureProductionPlace", "SignerRole"}) {
            if (firstChildByTagNS(signedSignatureProperties, XmlNamespaces.XADES_132, localName) != null) {
                found.add(localName);
            }
        }
        return found;
    }

    static List<byte[]> encapsulatedValues(Element revocationValues, String wrapperLocalName,
            String entryLocalName) {
        if (revocationValues == null) {
            return List.of();
        }
        Element wrapper = firstChildByTagNS(revocationValues, XmlNamespaces.XADES_132, wrapperLocalName);
        if (wrapper == null) {
            return List.of();
        }
        NodeList entries = wrapper.getElementsByTagNameNS(XmlNamespaces.XADES_132, entryLocalName);
        List<byte[]> result = new ArrayList<>(entries.getLength());
        for (int i = 0; i < entries.getLength(); i++) {
            String text = entries.item(i).getTextContent();
            result.add(BASE64.decode(text.trim()));
        }
        return result;
    }

    private static List<X509Certificate> certificateValues(Element unsignedSignatureProperties) {
        if (unsignedSignatureProperties == null) {
            return List.of();
        }
        Element wrapper =
            firstChildByTagNS(unsignedSignatureProperties, XmlNamespaces.XADES_132, "CertificateValues");
        if (wrapper == null) {
            return List.of();
        }
        NodeList entries =
            wrapper.getElementsByTagNameNS(XmlNamespaces.XADES_132, "EncapsulatedX509Certificate");
        List<X509Certificate> result = new ArrayList<>(entries.getLength());
        for (int i = 0; i < entries.getLength(); i++) {
            String text = entries.item(i).getTextContent();
            if (text != null && !text.isBlank()) {
                result.add(XmlCertificates.parse(text));
            }
        }
        return result;
    }

    private static String algorithmAttr(Element parent, String childLocalName) {
        Element child = parent == null ? null : firstChildByTagNS(parent, XmlNamespaces.XMLDSIG, childLocalName);
        return child == null ? null : emptyToNull(child.getAttribute("Algorithm"));
    }

    private static byte[] base64OfChild(Element parent, String ns, String localName) {
        String text = firstChildTextByTagNS(parent, ns, localName);
        return text == null ? null : BASE64.decode(text.trim());
    }

    private static String firstChildTextByTagNS(Element parent, String ns, String localName) {
        Element child = firstChildByTagNS(parent, ns, localName);
        return child == null ? null : child.getTextContent();
    }

    static Element firstChildByTagNS(Element parent, String ns, String localName) {
        if (parent == null) {
            return null;
        }
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && localName.equals(n.getLocalName())
                    && (ns == null || ns.equals(n.getNamespaceURI()))) {
                return (Element) n;
            }
        }
        return null;
    }

    private static Element firstChildByLocalName(Element parent, String localName) {
        return firstChildByTagNS(parent, null, localName);
    }

    private static List<Element> childrenByLocalName(Element parent, String localName) {
        List<Element> result = new ArrayList<>();
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && localName.equals(n.getLocalName())) {
                result.add((Element) n);
            }
        }
        return result;
    }

    private static String emptyToNull(String s) {
        return s == null || s.isEmpty() ? null : s;
    }
}
