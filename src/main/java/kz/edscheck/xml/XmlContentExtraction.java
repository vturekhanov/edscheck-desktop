package kz.edscheck.xml;

import java.util.Locale;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class XmlContentExtraction {
    private XmlContentExtraction() {
    }

    public static XmlExtractionPlan plan(byte[] container, String containerFileName) {
        Document doc = XmlFormatDetector.parseSecurely(container);
        DetectedXml detected = XmlFormatDetector.detect(doc);

        if (detected.format() == XmlContainerFormat.XMLESF) {
            EsfInvoice invoice = EsfParser.parse(doc);
            return new XmlExtractionPlan(defaultName(containerFileName, "invoiceBody"), invoice.signedBytes());
        }
        if (detected.format() == XmlContainerFormat.XADES_DETACHED
                || detected.format() == XmlContainerFormat.XMLDSIG_DETACHED) {
            throw new ContainerException(
                Messages.get(MsgKey.XML_CONTENT_EXTRACTION_NOTHING_TO_EXTRACT_DETACHED));
        }
        byte[] document = envelopedDocumentBytes(doc);
        return new XmlExtractionPlan(defaultName(containerFileName, "document"), document);
    }

    private static byte[] envelopedDocumentBytes(Document doc) {
        XmlCrypto.ensureInitialized();
        NodeList sigNodes = doc.getElementsByTagNameNS(XmlNamespaces.XMLDSIG, "Signature");
        Element sigEl = (Element) sigNodes.item(0);
        try {
            XMLSignature sig = new XMLSignature(sigEl, "");
            SignedInfo signedInfo = sig.getSignedInfo();
            for (int i = 0; i < signedInfo.getLength(); i++) {
                Reference ref = signedInfo.item(i);
                String uri = ref.getURI();
                if (uri == null || uri.isEmpty()) {
                    return ref.getReferencedBytes();
                }
            }
        } catch (XMLSecurityException e) {
            throw new ContainerException(Messages.get(MsgKey.XML_CONTENT_EXTRACTION_FAILED, e.getMessage()), e);
        }
        throw new ContainerException(Messages.get(MsgKey.XML_CONTENT_EXTRACTION_NO_DOCUMENT_REFERENCE));
    }

    private static String defaultName(String containerFileName, String suffix) {
        String lower = containerFileName.toLowerCase(Locale.ROOT);
        String base = lower.endsWith(".xml")
            ? containerFileName.substring(0, containerFileName.length() - 4) : containerFileName;
        return base + "-" + suffix + ".xml";
    }
}
