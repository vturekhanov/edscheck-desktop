package kz.edscheck.xml;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

final class XmlSecurityChecks {
    static final String XPATH_FILTER2_NS = "http://www.w3.org/2002/06/xmldsig-filter2";

    private static final String XPATH_FILTER2_FORM_BY_LOCAL_NAME =
        "//*[local-name()='Signature' and namespace-uri()='" + XmlNamespaces.XMLDSIG + "']";

    private static final Pattern XPATH_FILTER2_FORM_DESCENDANT =
        Pattern.compile("/descendant::([A-Za-z_][A-Za-z0-9_]*):Signature");

    private static final Pattern XPATH_WHITESPACE = Pattern.compile("[ \\t\\r\\n]+");

    private XmlSecurityChecks() {
    }

    static void validate(Document doc, List<ParsedXmlSignature> signatures) {
        checkNoManifest(doc);
        checkNoDuplicateIds(doc);

        NodeList signatureElements = doc.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Signature");
        for (ParsedXmlSignature signature : signatures) {
            checkAlgorithmWhitelist(signature);
            checkXPathFilter2NarrowForm((Element) signatureElements.item(signature.index()));
            if (signature.xades()) {
                checkSignedPropertiesActuallyCovered(doc, signature);
            }
        }
    }

    private static void checkNoManifest(Document doc) {
        if (doc.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Manifest").getLength() > 0) {
            throw new ContainerException(Messages.get(MsgKey.XML_MANIFEST_NOT_SUPPORTED));
        }
    }

    private static void checkNoDuplicateIds(Document doc) {
        walkForDuplicateIds(doc.getDocumentElement(), new HashSet<>());
    }

    private static void walkForDuplicateIds(Element el, Set<String> seen) {
        if (el == null) {
            return;
        }
        String id = el.getAttribute("Id");
        if (!id.isEmpty() && !seen.add(id)) {
            throw new ContainerException(Messages.get(MsgKey.XML_DUPLICATE_ID, id));
        }
        NodeList children = el.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE) {
                walkForDuplicateIds((Element) n, seen);
            }
        }
    }

    private static void checkAlgorithmWhitelist(ParsedXmlSignature signature) {
        requireKnown(signature.canonicalizationMethod(), XmlAlgorithms.CANONICALIZATION,
            MsgKey.XML_CANONICALIZATION_NOT_SUPPORTED);
        requireKnown(signature.signatureMethod(), XmlAlgorithms.SIGNATURE_METHOD,
            MsgKey.XML_SIGNATURE_ALGORITHM_NOT_SUPPORTED);
        if (signature.signatureTimestampCanonicalizationMethod() != null) {
            requireKnown(signature.signatureTimestampCanonicalizationMethod(), XmlAlgorithms.CANONICALIZATION,
                MsgKey.XML_CANONICALIZATION_NOT_SUPPORTED);
        }
        for (XmlReference ref : signature.references()) {
            requireKnown(ref.digestMethod(), XmlAlgorithms.DIGEST_METHOD,
                MsgKey.XML_DIGEST_ALGORITHM_NOT_SUPPORTED);
            for (String transform : ref.transforms()) {
                requireKnown(transform, XmlAlgorithms.TRANSFORM, MsgKey.XML_TRANSFORM_NOT_SUPPORTED);
            }
        }
    }

    private static void requireKnown(String algorithm, Set<String> whitelist, MsgKey key) {
        if (algorithm == null || !whitelist.contains(algorithm)) {
            throw new ContainerException(Messages.get(key, algorithm == null ? "(отсутствует)" : algorithm));
        }
    }

    private static void checkXPathFilter2NarrowForm(Element signature) {
        Element signedInfo = XmlSignatureParser.firstChildByTagNS(signature, XmlNamespaces.XMLDSIG, "SignedInfo");
        if (signedInfo == null) {
            return;
        }
        NodeList transforms = signedInfo.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Transform");
        for (int i = 0; i < transforms.getLength(); i++) {
            Element transform = (Element) transforms.item(i);
            if (!XPATH_FILTER2_NS.equals(transform.getAttribute("Algorithm"))) {
                continue;
            }
            NodeList xpathNodes = transform.getElementsByTagNameNS(XPATH_FILTER2_NS, "XPath");
            if (xpathNodes.getLength() == 0) {
                throw new ContainerException(Messages.get(MsgKey.XML_XPATH_FILTER2_NOT_SUPPORTED, "(нет XPath)"));
            }
            for (int j = 0; j < xpathNodes.getLength(); j++) {
                Element xpath = (Element) xpathNodes.item(j);
                String filterAttr = xpath.getAttribute("Filter");
                String expr = normalizeWhitespace(expressionAsEngineReadsIt(xpath));
                if (!"subtract".equals(filterAttr) || !isRecognizedForm(xpath, expr)) {
                    throw new ContainerException(Messages.get(MsgKey.XML_XPATH_FILTER2_NOT_SUPPORTED,
                        "Filter=\"" + filterAttr + "\" " + expr));
                }
            }
        }
    }

    private static String expressionAsEngineReadsIt(Element xpath) {
        StringBuilder text = new StringBuilder();
        for (Node child = xpath.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() != Node.TEXT_NODE) {
                throw new ContainerException(Messages.get(MsgKey.XML_XPATH_FILTER2_NON_TEXT_CONTENT));
            }
            text.append(((Text) child).getData());
        }
        return text.toString();
    }

    private static boolean isRecognizedForm(Element xpath, String expr) {
        if (XPATH_FILTER2_FORM_BY_LOCAL_NAME.equals(expr)) {
            return true;
        }
        Matcher m = XPATH_FILTER2_FORM_DESCENDANT.matcher(expr);
        return m.matches() && XmlNamespaces.XMLDSIG.equals(xpath.lookupNamespaceURI(m.group(1)));
    }

    private static String normalizeWhitespace(String text) {
        return XPATH_WHITESPACE.matcher(text).replaceAll(" ").replaceAll("^ | $", "");
    }

    private static void checkSignedPropertiesActuallyCovered(Document doc, ParsedXmlSignature signature) {
        Element qualifyingProperties = XmlSignatureParser.matchingQualifyingProperties(doc, signature.id());
        Element signedProperties = qualifyingProperties == null ? null
            : XmlSignatureParser.firstChildByTagNS(qualifyingProperties, XmlNamespaces.XADES_132, "SignedProperties");
        if (signedProperties == null) {
            throw new ContainerException(Messages.get(MsgKey.XML_SIGNED_PROPERTIES_NOT_COVERED));
        }
        String wantedUri = "#" + signedProperties.getAttribute("Id");
        for (XmlReference ref : signature.references()) {
            if (XmlNamespaces.XADES_SIGNED_PROPERTIES_TYPE.equals(ref.type()) && wantedUri.equals(ref.uri())) {
                return;
            }
        }
        throw new ContainerException(Messages.get(MsgKey.XML_SIGNED_PROPERTIES_NOT_COVERED));
    }
}
