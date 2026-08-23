package kz.edscheck.xml;

import java.util.List;

record DetectedXml(XmlContainerFormat format, List<ParsedXmlSignature> signatures) {
}
