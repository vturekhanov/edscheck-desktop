package kz.edscheck.xml;

import java.io.IOException;
import java.io.InputStream;

import org.w3c.dom.Document;

import kz.edscheck.domain.DocumentSource;

public final class XmlDetect {

    private static final int PEEK_LIMIT = 4096;
    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private XmlDetect() {
    }

    public static boolean looksLikeXml(byte[] container) {
        return looksLikeXml(container, container.length);
    }

    public static boolean looksLikeXml(DocumentSource source) throws IOException {
        byte[] prefix = new byte[PEEK_LIMIT];
        int n;
        try (InputStream in = source.open()) {
            n = in.readNBytes(prefix, 0, prefix.length);
        }
        return looksLikeXml(prefix, n);
    }

    private static boolean looksLikeXml(byte[] buf, int len) {
        int i = 0;
        if (len >= UTF8_BOM.length
                && buf[0] == UTF8_BOM[0] && buf[1] == UTF8_BOM[1] && buf[2] == UTF8_BOM[2]) {
            i = UTF8_BOM.length;
        }
        while (i < len) {
            byte b = buf[i];
            if (!isXmlWhitespace(b)) {
                return b == '<';
            }
            i++;
        }
        return false;
    }

    private static boolean isXmlWhitespace(byte b) {
        return b == 0x20 || b == 0x09 || b == 0x0D || b == 0x0A;
    }

    public static boolean looksLikeDetached(byte[] container) {
        try {
            Document doc = XmlFormatDetector.parseSecurely(container);
            XmlContainerFormat format = XmlFormatDetector.detect(doc).format();
            return format == XmlContainerFormat.XMLDSIG_DETACHED || format == XmlContainerFormat.XADES_DETACHED;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
