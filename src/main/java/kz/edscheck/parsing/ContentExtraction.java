package kz.edscheck.parsing;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;

import kz.edscheck.domain.DocumentSource;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class ContentExtraction {

    private static final long FALLBACK_MAX_BYTES = 500L * 1024 * 1024;

    private ContentExtraction() {
    }

    public static void extract(DocumentSource source, Path target) throws IOException {
        writeAtomically(target, out -> extractInto(source, out));
    }

    public static void copyAtomically(DocumentSource source, Path target) throws IOException {
        writeAtomically(target, out -> {
            try (InputStream in = source.open()) {
                in.transferTo(out);
            }
        });
    }

    @FunctionalInterface
    private interface IOWriter {
        void write(OutputStream out) throws IOException;
    }

    private static void writeAtomically(Path target, IOWriter writer) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        Path tmp = Files.createTempFile(dir, "eds-extract-", ".tmp");
        try {
            try (OutputStream out = Files.newOutputStream(tmp)) {
                writer.write(out);
            }
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static void extractInto(DocumentSource source, OutputStream out) throws IOException {
        try {
            AttachedSplitter.tryExtract(source, out);
            return;
        } catch (AttachedSplitter.SplitFailedException e) {

        }
        byte[] bytes = readBounded(source, FALLBACK_MAX_BYTES);
        if (bytes == null) {
            throw new ContainerException(Messages.get(
                MsgKey.CONTENT_EXTRACTION_TOO_LARGE_FOR_FALLBACK, FALLBACK_MAX_BYTES / (1024 * 1024)));
        }
        if (!ContainerFormat.looksLikeCades(bytes)) {
            throw new ContainerException(Messages.get(MsgKey.CONTENT_EXTRACTION_UNRECOGNIZED_FORMAT));
        }
        if (!ContainerFormat.isAttached(bytes)) {
            throw new ContainerException(Messages.get(MsgKey.CONTENT_EXTRACTION_NOTHING_TO_EXTRACT_DETACHED));
        }
        out.write(extractEncapContent(bytes));
    }

    static byte[] extractEncapContent(byte[] cmsBytes) {
        Object asn1;
        try {
            asn1 = new ASN1InputStream(cmsBytes).readObject();
        } catch (IOException e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()), e);
        }
        ContentInfo outer = ContentInfo.getInstance(asn1);
        SignedData signedData = SignedData.getInstance(outer.getContent());
        DEREncodable content = signedData.getEncapContentInfo().getContent();
        ASN1OctetString octets = ASN1OctetString.getInstance(content);
        return octets.getOctets();
    }

    private static byte[] readBounded(DocumentSource source, long capBytes) throws IOException {
        try (InputStream in = source.open()) {
            byte[] buf = in.readNBytes((int) (capBytes + 1));
            return buf.length > capBytes ? null : buf;
        }
    }

    public static String defaultAttachedName(Path containerPath) {
        String name = containerPath.getFileName().toString();
        if (!name.toLowerCase(Locale.ROOT).endsWith(".cms")) {
            return null;
        }
        return name.substring(0, name.length() - 4);
    }

    public static String sanitizeBasename(String name) {
        if (name == null || name.isBlank()) {
            return "document";
        }
        String normalized = name.replace('\\', '/');
        String base = normalized.substring(normalized.lastIndexOf('/') + 1);
        if (base.isBlank() || ".".equals(base) || "..".equals(base)) {
            return "document";
        }
        return base;
    }
}
