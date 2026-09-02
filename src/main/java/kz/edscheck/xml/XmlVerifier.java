package kz.edscheck.xml;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.w3c.dom.Document;

import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.Encoding;
import kz.edscheck.domain.Signature;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.trace.Trace;

public final class XmlVerifier {

    static final long MAX_XML_BYTES = 500L * 1024 * 1024;

    private XmlVerifier() {
    }

    public static SignedContainer verify(VerificationRequest request, byte[] container) {
        return verify(request, container, null, Trace.NONE);
    }

    public static SignedContainer verify(VerificationRequest request, byte[] container, Trace trace) {
        return verify(request, container, null, trace);
    }

    public static SignedContainer verify(
            VerificationRequest request, byte[] container, DocumentSource document, Trace trace) {
        Document doc = XmlFormatDetector.parseSecurely(container);
        DetectedXml detected = XmlFormatDetector.detect(doc);
        XmlSecurityChecks.validate(doc, detected.signatures());

        if (detected.format() == XmlContainerFormat.XMLESF) {

            EsfInvoice invoice = EsfParser.parse(doc);
            Signature signature = EsfSignatureAssembler.assemble(invoice, request, trace);
            return new SignedContainer(
                request.containerPath(), Encoding.DER, 1, List.of(signature),
                detected.format().value(), null, aggregateAuthority(List.of(signature)));
        }

        List<Signature> signatures =
            XmlSignatureAssembler.assemble(doc, detected.signatures(), request, document, trace);
        return new SignedContainer(
            request.containerPath(), Encoding.DER, signatures.size(), signatures,
            detected.format().value(), null, aggregateAuthority(signatures));
    }

    private static String aggregateAuthority(List<Signature> signatures) {
        Set<String> ucs = signatures.stream()
            .map(Signature::authority).filter(Objects::nonNull).collect(Collectors.toSet());
        return ucs.size() == 1 ? ucs.iterator().next() : null;
    }

    public static SignedContainer verify(VerificationRequest request, DocumentSource container) {
        return verify(request, readBounded(container, MAX_XML_BYTES), Trace.NONE);
    }

    public static SignedContainer verify(VerificationRequest request, DocumentSource container, Trace trace) {
        return verify(request, readBounded(container, MAX_XML_BYTES), trace);
    }

    public static SignedContainer verify(
            VerificationRequest request, DocumentSource container, DocumentSource document, Trace trace) {
        return verify(request, readBounded(container, MAX_XML_BYTES), document, trace);
    }

    static byte[] readBounded(DocumentSource source, long maxBytes) {
        try (InputStream in = source.open()) {
            byte[] buf = in.readNBytes((int) Math.min(maxBytes + 1, Integer.MAX_VALUE));
            if (buf.length > maxBytes) {
                throw new ContainerException(Messages.get(MsgKey.XML_FILE_TOO_LARGE, maxBytes / (1024 * 1024)));
            }
            return buf;
        } catch (IOException e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
        }
    }
}
