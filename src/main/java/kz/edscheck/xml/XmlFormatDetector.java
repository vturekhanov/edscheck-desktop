package kz.edscheck.xml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

final class XmlFormatDetector {
    private static final String ESF_ROOT_LOCAL_NAME = "invoiceInfoContainer";
    private static final String ESF_INVOICE_INFO_LOCAL_NAME = "invoiceInfo";

    private static final ErrorHandler SILENT_ERROR_HANDLER = new ErrorHandler() {
        @Override
        public void warning(SAXParseException exception) {

        }

        @Override
        public void error(SAXParseException exception) throws SAXException {
            throw exception;
        }

        @Override
        public void fatalError(SAXParseException exception) throws SAXException {
            throw exception;
        }
    };

    private XmlFormatDetector() {
    }

    static Document parseSecurely(byte[] container) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));

            builder.setErrorHandler(SILENT_ERROR_HANDLER);
            return builder.parse(new ByteArrayInputStream(container));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new ContainerException(Messages.get(MsgKey.XML_NOT_PARSED, e.getMessage()), e);
        }
    }

    static DetectedXml detect(Document doc) {
        Element root = doc.getDocumentElement();
        if (root != null && ESF_ROOT_LOCAL_NAME.equals(root.getLocalName())) {
            int invoiceCount = root.getElementsByTagNameNS("*", ESF_INVOICE_INFO_LOCAL_NAME).getLength();
            if (invoiceCount > 1) {
                throw new ContainerException(Messages.get(MsgKey.XML_BATCH_ESF, invoiceCount));
            }
            if (invoiceCount == 1) {
                return new DetectedXml(XmlContainerFormat.XMLESF, List.of());
            }

        }

        List<ParsedXmlSignature> signatures = XmlSignatureParser.parseAll(doc);
        if (signatures.isEmpty()) {
            throw new ContainerException(Messages.get(MsgKey.XML_NOT_RECOGNIZED));
        }

        boolean allXades = true;
        Boolean detached = null;
        for (ParsedXmlSignature signature : signatures) {
            if (!signature.xades()) {
                allXades = false;
            }
            if (detached == null) {
                detached = signature.detached();
            } else if (detached != signature.detached()) {

                throw new ContainerException(Messages.get(MsgKey.XML_NOT_RECOGNIZED));
            }
        }

        boolean isDetached = Boolean.TRUE.equals(detached);
        XmlContainerFormat format;
        if (allXades) {
            format = isDetached ? XmlContainerFormat.XADES_DETACHED : XmlContainerFormat.XADES;
        } else {
            format = isDetached ? XmlContainerFormat.XMLDSIG_DETACHED : XmlContainerFormat.XMLDSIG;
        }
        return new DetectedXml(format, signatures);
    }
}
