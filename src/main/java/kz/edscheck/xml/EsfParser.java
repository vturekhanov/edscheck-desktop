package kz.edscheck.xml;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import kz.edscheck.domain.Certificate;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.Parsing;

final class EsfParser {
    private static final Base64.Decoder BASE64 = Base64.getMimeDecoder();
    private static final String INVOICE_INFO = "invoiceInfo";
    private static final String INVOICE_BODY = "invoiceBody";
    private static final String SIGNATURE = "signature";
    private static final String CERTIFICATE = "certificate";

    private EsfParser() {
    }

    static EsfInvoice parse(Document doc) {
        Element invoiceInfo = (Element) doc.getDocumentElement()
            .getElementsByTagNameNS("*", INVOICE_INFO).item(0);

        String bodyText = childText(invoiceInfo, INVOICE_BODY);
        String signatureText = childText(invoiceInfo, SIGNATURE);
        String certificateText = childText(invoiceInfo, CERTIFICATE);
        if (bodyText == null || signatureText == null || certificateText == null) {
            throw new ContainerException(Messages.get(MsgKey.XML_ESF_SIGNATURE_ABSENT));
        }

        byte[] signedBytes = bodyText.getBytes(StandardCharsets.UTF_8);
        byte[] signatureValue = BASE64.decode(signatureText.trim());
        X509Certificate certificateRaw = XmlCertificates.parse(certificateText);
        Certificate certificate = Parsing.certificateFields(certificateRaw);

        return new EsfInvoice(signedBytes, signatureValue, certificateRaw, certificate);
    }

    private static String childText(Element parent, String localName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && localName.equals(n.getLocalName())) {
                return n.getTextContent();
            }
        }
        return null;
    }
}
