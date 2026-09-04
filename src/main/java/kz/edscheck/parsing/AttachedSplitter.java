package kz.edscheck.parsing;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import kz.edscheck.domain.DocumentSource;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.trust.ActiveBackend;
import kz.edscheck.trust.DigestAlgorithms;

final class AttachedSplitter {
    private static final int STREAM_BUFFER = 1 << 16;

    private static final int EXTRACT_STREAM_BUFFER = 16 * 1024 * 1024;

    private static final long MAX_SMALL_FIELD_BYTES = 64L * 1024 * 1024;

    private AttachedSplitter() {
    }

    static final class SplitFailedException extends RuntimeException {
        SplitFailedException(String message) {
            super(message);
        }

        SplitFailedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    record Split(byte[] skeleton, Map<String, byte[]> digestsByOid) {
    }

    static Split trySplit(DocumentSource container) throws IOException {
        try (InputStream raw = container.open()) {
            Counting in = new Counting(raw);
            return split(in);
        }
    }

    static void tryExtract(DocumentSource container, OutputStream out) throws IOException {
        try (InputStream raw = container.open()) {
            Counting in = new Counting(raw);
            extract(in, out);
        }
    }

    private static void extract(Counting in, OutputStream out) throws IOException {
        Tlv outer = readTagLen(in);
        requireTag(outer, 0x30, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_CONTENT_INFO_SEQUENCE));

        Tlv oidTlv = readTagLen(in);
        requireTag(oidTlv, 0x06, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_CONTENT_TYPE_OID));
        byte[] oidFull = materializeFullTlv(in, oidTlv);
        ASN1ObjectIdentifier contentType = readAsn1(oidFull, ASN1ObjectIdentifier.class);
        if (!CMSObjectIdentifiers.signedData.equals(contentType)) {
            throw new SplitFailedException(
                Messages.get(MsgKey.ATTACHED_SPLITTER_WRONG_CONTENT_TYPE, contentType.getId()));
        }

        Tlv explicit0 = readTagLen(in);
        requireTag(explicit0, 0xA0, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_EXPLICIT0_CONTENT));

        Tlv signedDataTlv = readTagLen(in);
        requireTag(signedDataTlv, 0x30, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_SIGNED_DATA_SEQUENCE));

        Tlv versionTlv = readTagLen(in);
        requireTag(versionTlv, 0x02, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_VERSION));
        materializeFullTlv(in, versionTlv); 

        Tlv digestAlgsTlv = readTagLen(in);
        requireTag(digestAlgsTlv, 0x31, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_DIGEST_ALGORITHMS));
        materializeFullTlv(in, digestAlgsTlv); 

        Tlv encapTlv = readTagLen(in);
        requireTag(encapTlv, 0x30, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_ENCAP_CONTENT_INFO));
        long encapStart = in.count();
        long encapLimit = encapTlv.indefinite ? -1 : encapStart + encapTlv.length;

        Tlv eContentTypeTlv = readTagLen(in);
        requireTag(eContentTypeTlv, 0x06, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_ECONTENT_TYPE));
        materializeFullTlv(in, eContentTypeTlv); 

        Tlv eContentWrapper;
        if (encapTlv.indefinite) {
            eContentWrapper = readTlvOrEoc(in);
            if (eContentWrapper == null) {

                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ECONTENT_ABSENT));
            }
        } else {
            if (in.count() >= encapLimit) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ECONTENT_ABSENT));
            }
            eContentWrapper = readTagLen(in);
        }
        requireTag(eContentWrapper, 0xA0, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_ECONTENT_WRAPPER));
        Tlv octetTlv = readTagLen(in);
        if (octetTlv.tagByte != 0x04 && octetTlv.tagByte != 0x24) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ECONTENT_NOT_OCTET_STRING,
                Integer.toHexString(octetTlv.tagByte)));
        }
        streamOctetStringIntoOutput(in, octetTlv, out);
        closeIfIndefinite(in, eContentWrapper);
        closeIfIndefinite(in, encapTlv);

        if (!encapTlv.indefinite && in.count() != encapLimit) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ENCAP_LENGTH_MISMATCH));
        }
    }

    private static Split split(Counting in) throws IOException {
        Tlv outer = readTagLen(in);
        requireTag(outer, 0x30, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_CONTENT_INFO_SEQUENCE));

        Tlv oidTlv = readTagLen(in);
        requireTag(oidTlv, 0x06, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_CONTENT_TYPE_OID));
        byte[] oidFull = materializeFullTlv(in, oidTlv);
        ASN1ObjectIdentifier contentType = readAsn1(oidFull, ASN1ObjectIdentifier.class);
        if (!CMSObjectIdentifiers.signedData.equals(contentType)) {
            throw new SplitFailedException(
                Messages.get(MsgKey.ATTACHED_SPLITTER_WRONG_CONTENT_TYPE, contentType.getId()));
        }

        Tlv explicit0 = readTagLen(in);
        requireTag(explicit0, 0xA0, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_EXPLICIT0_CONTENT));

        Tlv signedDataTlv = readTagLen(in);
        requireTag(signedDataTlv, 0x30, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_SIGNED_DATA_SEQUENCE));
        long signedDataStart = in.count();
        long signedDataLimit = signedDataTlv.indefinite ? -1 : signedDataStart + signedDataTlv.length;

        Tlv versionTlv = readTagLen(in);
        requireTag(versionTlv, 0x02, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_VERSION));
        byte[] versionFull = materializeFullTlv(in, versionTlv);

        Tlv digestAlgsTlv = readTagLen(in);
        requireTag(digestAlgsTlv, 0x31, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_DIGEST_ALGORITHMS));
        byte[] digestAlgsFull = materializeFullTlv(in, digestAlgsTlv);
        Map<String, MessageDigest> mdByOid = digestsFromDeclaredAlgorithms(digestAlgsFull);

        Tlv encapTlv = readTagLen(in);
        requireTag(encapTlv, 0x30, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_ENCAP_CONTENT_INFO));
        long encapStart = in.count();
        long encapLimit = encapTlv.indefinite ? -1 : encapStart + encapTlv.length;

        Tlv eContentTypeTlv = readTagLen(in);
        requireTag(eContentTypeTlv, 0x06, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_ECONTENT_TYPE));
        byte[] eContentTypeFull = materializeFullTlv(in, eContentTypeTlv);

        Tlv eContentWrapper;
        if (encapTlv.indefinite) {
            eContentWrapper = readTlvOrEoc(in);
            if (eContentWrapper == null) {

                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ECONTENT_ABSENT));
            }
        } else {
            if (in.count() >= encapLimit) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ECONTENT_ABSENT));
            }
            eContentWrapper = readTagLen(in);
        }
        requireTag(eContentWrapper, 0xA0, Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECT_ECONTENT_WRAPPER));
        Tlv octetTlv = readTagLen(in);
        if (octetTlv.tagByte != 0x04 && octetTlv.tagByte != 0x24) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ECONTENT_NOT_OCTET_STRING,
                Integer.toHexString(octetTlv.tagByte)));
        }
        streamOctetStringIntoDigests(in, octetTlv, mdByOid.values());
        closeIfIndefinite(in, eContentWrapper);
        closeIfIndefinite(in, encapTlv);

        if (!encapTlv.indefinite && in.count() != encapLimit) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_ENCAP_LENGTH_MISMATCH));
        }

        byte[] tail;
        if (!signedDataTlv.indefinite) {
            long remaining = signedDataLimit - in.count();
            if (remaining < 0 || remaining > MAX_SMALL_FIELD_BYTES) {
                throw new SplitFailedException(
                    Messages.get(MsgKey.ATTACHED_SPLITTER_TAIL_UNEXPECTED_SIZE, remaining));
            }
            tail = readExactly(in, remaining);
        } else {
            ByteArrayOutputStream tailOut = new ByteArrayOutputStream();
            while (true) {
                Tlv child = readTlvOrEoc(in);
                if (child == null) {
                    break;
                }
                writeMaterializedTlv(tailOut, child, in);
                if (tailOut.size() > MAX_SMALL_FIELD_BYTES) {
                    throw new SplitFailedException(
                        Messages.get(MsgKey.ATTACHED_SPLITTER_TAIL_INDEFINITE_TOO_LARGE));
                }
            }
            tail = tailOut.toByteArray();
        }
        closeIfIndefinite(in, signedDataTlv);
        closeIfIndefinite(in, explicit0);
        closeIfIndefinite(in, outer);

        byte[] skeleton = buildSkeleton(oidFull, versionFull, digestAlgsFull, eContentTypeFull, tail);
        Map<String, byte[]> digestsByOid = new LinkedHashMap<>();
        for (Map.Entry<String, MessageDigest> e : mdByOid.entrySet()) {
            digestsByOid.put(e.getKey(), e.getValue().digest());
        }
        return new Split(skeleton, digestsByOid);
    }

    private static byte[] buildSkeleton(
            byte[] oidFull, byte[] versionFull, byte[] digestAlgsFull,
            byte[] eContentTypeFull, byte[] tail) throws IOException {
        byte[] encapValue = eContentTypeFull; 
        byte[] encapTlvBytes = wrapTlv(0x30, encapValue);

        ByteArrayOutputStream signedDataValue = new ByteArrayOutputStream();
        signedDataValue.write(versionFull);
        signedDataValue.write(digestAlgsFull);
        signedDataValue.write(encapTlvBytes);
        signedDataValue.write(tail);
        byte[] signedDataTlvBytes = wrapTlv(0x30, signedDataValue.toByteArray());

        byte[] explicit0Bytes = wrapTlv(0xA0, signedDataTlvBytes);

        ByteArrayOutputStream contentInfoValue = new ByteArrayOutputStream();
        contentInfoValue.write(oidFull);
        contentInfoValue.write(explicit0Bytes);
        return wrapTlv(0x30, contentInfoValue.toByteArray());
    }

    private static byte[] wrapTlv(int tagByte, byte[] value) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length + 8);
        out.write(tagByte);
        writeDefiniteLength(out, value.length);
        out.write(value);
        return out.toByteArray();
    }

    private static Map<String, MessageDigest> digestsFromDeclaredAlgorithms(byte[] digestAlgsFullTlv) {
        ASN1Set set = readAsn1(digestAlgsFullTlv, ASN1Set.class);
        Map<String, MessageDigest> mdByOid = new LinkedHashMap<>();
        for (int i = 0; i < set.size(); i++) {
            AlgorithmIdentifier alg;
            try {
                alg = AlgorithmIdentifier.getInstance(set.getObjectAt(i));
            } catch (Exception e) {
                continue; 
            }
            String oid = alg.getAlgorithm().getId();
            if (mdByOid.containsKey(oid)) {
                continue;
            }
            String jceName = DigestAlgorithms.jceName(oid);
            if (jceName == null) {
                continue;
            }
            try {
                mdByOid.put(oid, MessageDigest.getInstance(jceName, ActiveBackend.current().jceProviderName()));
            } catch (Exception e) {

            }
        }
        return mdByOid;
    }

    @SuppressWarnings("unchecked")
    private static <T> T readAsn1(byte[] fullTlv, Class<T> type) {
        try {
            Object obj = new ASN1InputStream(fullTlv).readObject();
            if (!type.isInstance(obj)) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_UNEXPECTED_ASN1_TYPE,
                    type.getSimpleName(), obj == null ? "null" : obj.getClass().getSimpleName()));
            }
            return (T) obj;
        } catch (SplitFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new SplitFailedException(
                Messages.get(MsgKey.ATTACHED_SPLITTER_FIELD_PARSE_FAILED, e.getMessage()), e);
        }
    }

    private static void streamOctetStringIntoDigests(
            Counting in, Tlv tlv, Iterable<MessageDigest> digests) throws IOException {
        if (!tlv.constructed) {
            streamExactlyThroughDigests(in, tlv.length, digests);
            return;
        }
        if (!tlv.indefinite) {
            long limit = in.count() + tlv.length;
            while (in.count() < limit) {
                Tlv child = readTagLen(in);
                streamOctetStringIntoDigests(in, child, digests);
            }
            if (in.count() != limit) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_CHUNK_OUT_OF_BOUNDS));
            }
            return;
        }
        while (true) {
            Tlv child = readTlvOrEoc(in);
            if (child == null) {
                break;
            }
            streamOctetStringIntoDigests(in, child, digests);
        }
    }

    private static void streamExactlyThroughDigests(
            InputStream in, long length, Iterable<MessageDigest> digests) throws IOException {
        byte[] buf = new byte[STREAM_BUFFER];
        long remaining = length;
        while (remaining > 0) {
            int chunk = (int) Math.min(buf.length, remaining);
            int n = in.read(buf, 0, chunk);
            if (n == -1) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_UNEXPECTED_EOF_ECONTENT));
            }
            for (MessageDigest md : digests) {
                md.update(buf, 0, n);
            }
            remaining -= n;
        }
    }

    private static void streamOctetStringIntoOutput(Counting in, Tlv tlv, OutputStream out) throws IOException {
        if (!tlv.constructed) {
            streamExactlyThroughOutput(in, tlv.length, out);
            return;
        }
        if (!tlv.indefinite) {
            long limit = in.count() + tlv.length;
            while (in.count() < limit) {
                Tlv child = readTagLen(in);
                streamOctetStringIntoOutput(in, child, out);
            }
            if (in.count() != limit) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_CHUNK_OUT_OF_BOUNDS));
            }
            return;
        }
        while (true) {
            Tlv child = readTlvOrEoc(in);
            if (child == null) {
                break;
            }
            streamOctetStringIntoOutput(in, child, out);
        }
    }

    private static void streamExactlyThroughOutput(InputStream in, long length, OutputStream out) throws IOException {
        byte[] buf = new byte[EXTRACT_STREAM_BUFFER];
        long remaining = length;
        while (remaining > 0) {
            int chunk = (int) Math.min(buf.length, remaining);
            int n = in.read(buf, 0, chunk);
            if (n == -1) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_UNEXPECTED_EOF_ECONTENT));
            }
            out.write(buf, 0, n);
            remaining -= n;
        }
    }

    private record Tlv(int tagByte, boolean constructed, long length, boolean indefinite) {
    }

    private static final class Counting extends FilterInputStream {
        private long count;

        Counting(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b != -1) {
                count++;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) {
                count += n;
            }
            return n;
        }

        long count() {
            return count;
        }
    }

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b == -1) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_UNEXPECTED_EOF_TLV));
        }
        return b;
    }

    private static Tlv readTagLenFrom(InputStream in, int tagByte) throws IOException {
        if ((tagByte & 0x1F) == 0x1F) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_MULTIBYTE_TAG_UNSUPPORTED));
        }
        boolean constructed = (tagByte & 0x20) != 0;
        int lenByte = readByte(in);
        if (lenByte == 0x80) {
            if (!constructed) {
                throw new SplitFailedException(
                    Messages.get(MsgKey.ATTACHED_SPLITTER_INDEFINITE_LENGTH_PRIMITIVE));
            }
            return new Tlv(tagByte, true, -1, true);
        }
        if ((lenByte & 0x80) == 0) {
            return new Tlv(tagByte, constructed, lenByte, false);
        }
        int numLenBytes = lenByte & 0x7F;
        if (numLenBytes == 0 || numLenBytes > 8) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_UNSUPPORTED_LENGTH_FORM));
        }
        long len = 0;
        for (int i = 0; i < numLenBytes; i++) {
            len = (len << 8) | (readByte(in) & 0xFFL);
        }
        if (len < 0) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_LENGTH_TOO_LARGE));
        }
        return new Tlv(tagByte, constructed, len, false);
    }

    private static Tlv readTagLen(InputStream in) throws IOException {
        return readTagLenFrom(in, readByte(in));
    }

    private static Tlv readTlvOrEoc(InputStream in) throws IOException {
        int first = readByte(in);
        if (first == 0x00) {
            int second = readByte(in);
            if (second != 0x00) {
                throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECTED_EOC));
            }
            return null;
        }
        return readTagLenFrom(in, first);
    }

    private static byte[] materializeValue(InputStream in, Tlv tlv) throws IOException {
        if (!tlv.indefinite) {
            if (tlv.length > MAX_SMALL_FIELD_BYTES) {
                throw new SplitFailedException(
                    Messages.get(MsgKey.ATTACHED_SPLITTER_FIELD_TOO_LARGE, tlv.length));
            }
            return readExactly(in, tlv.length);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            Tlv child = readTlvOrEoc(in);
            if (child == null) {
                break;
            }
            writeMaterializedTlv(out, child, in);
            if (out.size() > MAX_SMALL_FIELD_BYTES) {
                throw new SplitFailedException(
                    Messages.get(MsgKey.ATTACHED_SPLITTER_FIELD_INDEFINITE_TOO_LARGE));
            }
        }
        return out.toByteArray();
    }

    private static void writeMaterializedTlv(OutputStream out, Tlv tlv, InputStream in) throws IOException {
        byte[] value = materializeValue(in, tlv);
        out.write(tlv.tagByte);
        writeDefiniteLength(out, value.length);
        out.write(value, 0, value.length);
    }

    private static byte[] materializeFullTlv(InputStream in, Tlv tlv) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeMaterializedTlv(out, tlv, in);
        return out.toByteArray();
    }

    private static byte[] readExactly(InputStream in, long n) throws IOException {
        if (n > MAX_SMALL_FIELD_BYTES) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_READ_TOO_LARGE, n));
        }
        byte[] buf = new byte[(int) n];
        int off = 0;
        while (off < buf.length) {
            int r = in.read(buf, off, buf.length - off);
            if (r == -1) {
                throw new SplitFailedException(
                    Messages.get(MsgKey.ATTACHED_SPLITTER_UNEXPECTED_EOF_READING_TLV, n));
            }
            off += r;
        }
        return buf;
    }

    private static void writeDefiniteLength(OutputStream out, int len) throws IOException {
        if (len < 0x80) {
            out.write(len);
            return;
        }
        int numBytes = 1;
        int tmp = len;
        while ((tmp >>>= 8) != 0) {
            numBytes++;
        }
        out.write(0x80 | numBytes);
        for (int i = numBytes - 1; i >= 0; i--) {
            out.write((len >>> (8 * i)) & 0xFF);
        }
    }

    private static void closeIfIndefinite(InputStream in, Tlv tlv) throws IOException {
        if (!tlv.indefinite) {
            return;
        }
        int b1 = readByte(in);
        int b2 = readByte(in);
        if (b1 != 0x00 || b2 != 0x00) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_EXPECTED_CLOSING_EOC));
        }
    }

    private static void requireTag(Tlv tlv, int expectedTagByte, String what) {
        if (tlv.tagByte != expectedTagByte) {
            throw new SplitFailedException(Messages.get(MsgKey.ATTACHED_SPLITTER_TAG_MISMATCH,
                what, Integer.toHexString(expectedTagByte), Integer.toHexString(tlv.tagByte)));
        }
    }
}
