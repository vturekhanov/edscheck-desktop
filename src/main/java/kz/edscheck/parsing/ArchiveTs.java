package kz.edscheck.parsing;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class ArchiveTs {
    public static final String OID_ARCHIVE_TIMESTAMP_V3 = "0.4.0.1733.2.4"; 
    public static final String OID_ATS_HASH_INDEX_V3 = "0.4.0.19122.1.5";   
    private static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

    private static final ASN1ObjectIdentifier OID_ARCHIVE_TS_V3_DER =
        new ASN1ObjectIdentifier(OID_ARCHIVE_TIMESTAMP_V3);
    private static final ASN1ObjectIdentifier OID_ATS_HASH_INDEX_V3_DER =
        new ASN1ObjectIdentifier(OID_ATS_HASH_INDEX_V3);

    private ArchiveTs() {
    }

    public static final class ParsedArchiveTimestamp {
        public final int position;
        public byte[] tstDer;
        public Instant genTime;
        public X509Certificate tsaCert;
        public List<X509Certificate> tsaCerts = List.of();
        public Boolean tsaEkuOk;
        public String hashIndAlgOid;
        public String imprintAlgOid;
        public byte[] recordedImprint;
        public List<byte[]> recordedCertHashes = List.of();
        public List<byte[]> recordedCrlHashes = List.of();
        public List<byte[]> recordedAttrHashes = List.of();
        public List<byte[]> certBlobs = List.of();
        public List<byte[]> crlBlobs = List.of();
        public List<byte[]> attrBlobs = List.of();
        public byte[] imprintBlob;
        public String parseError;

        public ParsedArchiveTimestamp(int position) {
            this.position = position;
        }
    }

    public static List<ParsedArchiveTimestamp> parseArchiveTimestamps(
            SignerInformation si, List<X509Certificate> containerCerts,
            List<byte[]> crlBlobs, byte[] eContentTypeDer) {
        AttributeTable ut = si.getUnsignedAttributes();
        List<Object> values = archiveTsValues(ut);
        if (values.isEmpty()) {
            return List.of();
        }

        List<byte[]> certBlobs = new ArrayList<>();
        for (X509Certificate c : containerCerts) {
            try {
                certBlobs.add(c.getEncoded());
            } catch (Exception ignored) {

            }
        }
        List<byte[]> nonV3Blobs = nonV3AttrBlobs(ut);
        byte[] imprintPrefix = imprintPrefix(si, eContentTypeDer);

        List<ParsedArchiveTimestamp> marks = new ArrayList<>();
        for (int position = 0; position < values.size(); position++) {
            marks.add(parseOne(position, values.get(position), certBlobs, crlBlobs,
                nonV3Blobs, marks, imprintPrefix));
        }
        return marks;
    }

    private static ParsedArchiveTimestamp parseOne(
            int position, Object value, List<byte[]> certBlobs, List<byte[]> crlBlobs,
            List<byte[]> nonV3Blobs, List<ParsedArchiveTimestamp> earlierMarks,
            byte[] imprintPrefix) {
        ParsedArchiveTimestamp mark = new ParsedArchiveTimestamp(position);
        mark.certBlobs = certBlobs;
        mark.crlBlobs = crlBlobs;

        List<byte[]> attrBlobs = new ArrayList<>(nonV3Blobs);
        byte[] v3TypeDer = derEncoded(OID_ARCHIVE_TS_V3_DER);
        for (int j = 0; j < position; j++) {
            attrBlobs.add(concat(v3TypeDer, earlierMarks.get(j).tstDer));
        }
        mark.attrBlobs = attrBlobs;

        ContentInfo ci;
        CMSSignedData tstCms;
        SignerInformation tstSi;
        TimeStampToken tst;
        try {
            mark.tstDer = ((ASN1Encodable) value).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            ci = ContentInfo.getInstance(value);
            tstCms = new CMSSignedData(ci);
            Collection<SignerInformation> tstSigners = tstCms.getSignerInfos().getSigners();
            tstSi = tstSigners.iterator().next();
            tst = new TimeStampToken(ci);
        } catch (Exception e) {
            mark.parseError = Messages.get(MsgKey.ARCHIVE_TS_TST_PARSE_FAILED, e.getMessage());
            return mark;
        }

        try {
            var genTimeDate = tst.getTimeStampInfo().getGenTime();
            mark.genTime = genTimeDate != null ? genTimeDate.toInstant() : null;
            mark.imprintAlgOid = tst.getTimeStampInfo().getMessageImprintAlgOID().getId();
            mark.recordedImprint = tst.getTimeStampInfo().getMessageImprintDigest();

            Store<X509CertificateHolder> tcs = tstCms.getCertificates();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> tsaCertColl = tcs.getMatches(tstSi.getSID());
            List<X509Certificate> tsaCerts = new ArrayList<>();
            for (X509CertificateHolder h : tcs.getMatches(null)) {
                tsaCerts.add(converter.getCertificate(h));
            }
            mark.tsaCerts = tsaCerts;
            if (!tsaCertColl.isEmpty()) {
                mark.tsaCert = converter.getCertificate(tsaCertColl.iterator().next());
                try {
                    List<String> eku = mark.tsaCert.getExtendedKeyUsage();
                    mark.tsaEkuOk = eku != null && eku.contains("1.3.6.1.5.5.7.3.8");
                } catch (CertificateParsingException e) {
                    mark.tsaEkuOk = null;
                }
            }
        } catch (Exception e) {
            mark.parseError = Messages.get(MsgKey.ARCHIVE_TS_TST_PARSE_FAILED, e.getMessage());
            return mark;
        }

        byte[] atsIndexDer;
        try {
            AttributeTable tstUt = tstSi.getUnsignedAttributes();
            Attribute atsAttr = tstUt == null ? null : tstUt.get(OID_ATS_HASH_INDEX_V3_DER);
            if (atsAttr == null) {
                mark.parseError = Messages.get(MsgKey.ARCHIVE_TS_NO_ATS_HASH_INDEX);
                return mark;
            }
            Object atsValue = atsAttr.getAttrValues().getObjectAt(0);
            atsIndexDer = ((ASN1Encodable) atsValue).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            ASN1Sequence ats = ASN1Sequence.getInstance(atsValue);
            AlgorithmIdentifier hashIndAlg = AlgorithmIdentifier.getInstance(ats.getObjectAt(0));
            mark.hashIndAlgOid = hashIndAlg.getAlgorithm().getId();
            mark.recordedCertHashes = octetStrings(ats.getObjectAt(1));
            mark.recordedCrlHashes = octetStrings(ats.getObjectAt(2));
            mark.recordedAttrHashes = octetStrings(ats.getObjectAt(3));
        } catch (Exception e) {
            mark.parseError = Messages.get(MsgKey.ARCHIVE_TS_ATS_HASH_INDEX_PARSE_FAILED, e.getMessage());
            return mark;
        }

        if (imprintPrefix == null) {
            mark.parseError = Messages.get(MsgKey.ARCHIVE_TS_IMPRINT_NO_MESSAGE_DIGEST);
            return mark;
        }
        mark.imprintBlob = concat(imprintPrefix, atsIndexDer);
        return mark;
    }

    public static String evaluateHashes(
            ParsedArchiveTimestamp mark, List<byte[]> computedCertHashes,
            List<byte[]> computedCrlHashes, List<byte[]> computedAttrHashes,
            byte[] computedImprint) {
        if (mark.parseError != null) {
            return mark.parseError;
        }
        String certFail = compareHashSets(mark.recordedCertHashes, computedCertHashes,
            Messages.get(MsgKey.ARCHIVE_TS_CERT_HASHES_MISMATCH));
        if (certFail != null) {
            return certFail;
        }
        String crlFail = compareHashSets(mark.recordedCrlHashes, computedCrlHashes,
            Messages.get(MsgKey.ARCHIVE_TS_CRL_HASHES_MISMATCH));
        if (crlFail != null) {
            return crlFail;
        }
        String attrFail = compareHashSets(mark.recordedAttrHashes, computedAttrHashes,
            Messages.get(MsgKey.ARCHIVE_TS_ATTR_HASHES_MISMATCH));
        if (attrFail != null) {
            return attrFail;
        }
        if (computedImprint == null || mark.recordedImprint == null) {
            return Messages.get(MsgKey.ARCHIVE_TS_IMPRINT_NOT_RECOMPUTED);
        }
        if (!java.util.Arrays.equals(computedImprint, mark.recordedImprint)) {
            return Messages.get(MsgKey.ARCHIVE_TS_IMPRINT_MISMATCH);
        }
        return null;
    }

    private static String compareHashSets(List<byte[]> recorded, List<byte[]> computed, String reason) {
        if (!allRecordedHashesFound(recorded, computed)) {
            return reason;
        }
        return null;
    }

    private static boolean allRecordedHashesFound(List<byte[]> recorded, List<byte[]> computed) {
        List<String> remaining = toHexList(computed);
        for (byte[] r : recorded) {
            if (!remaining.remove(hex(r))) {
                return false;
            }
        }
        return true;
    }

    private static List<String> toHexList(List<byte[]> blobs) {
        List<String> out = new ArrayList<>(blobs.size());
        for (byte[] b : blobs) {
            out.add(hex(b));
        }
        return out;
    }

    public static String markFailure(
            String parseError, Boolean tsaSigOk, Boolean tsaLinksOk, Boolean tsaAnchored,
            Boolean tsaValidityOk, Boolean tsaEkuOk, String revocationFailure, String hashFailure) {
        if (parseError != null) {
            return parseError;
        }
        if (!Boolean.TRUE.equals(tsaSigOk)) {
            return Messages.get(MsgKey.ARCHIVE_TS_TST_SIGNATURE_UNCONFIRMED);
        }
        if (!Boolean.TRUE.equals(tsaLinksOk) || !Boolean.TRUE.equals(tsaAnchored)) {
            return Messages.get(MsgKey.ARCHIVE_TS_TSA_CHAIN_NOT_ANCHORED);
        }
        if (!Boolean.TRUE.equals(tsaValidityOk)) {
            return Messages.get(MsgKey.ARCHIVE_TS_TSA_CERT_EXPIRED);
        }
        if (!Boolean.TRUE.equals(tsaEkuOk)) {
            return Messages.get(MsgKey.ARCHIVE_TS_TSA_NO_TIMESTAMPING_EKU);
        }
        if (revocationFailure != null) {
            return revocationFailure;
        }
        return hashFailure;
    }

    public static Boolean markTsaCertInValidity(ParsedArchiveTimestamp mark) {
        if (mark.tsaCert == null || mark.genTime == null) {
            return null;
        }
        Instant notBefore = mark.tsaCert.getNotBefore().toInstant();
        Instant notAfter = mark.tsaCert.getNotAfter().toInstant();
        return !mark.genTime.isBefore(notBefore) && !mark.genTime.isAfter(notAfter);
    }

    public record Failure(int position, String reason) {
    }

    public record Combined(boolean ok, String detail) {
    }

    public static Combined combineResults(int total, List<Failure> failures) {
        if (!failures.isEmpty()) {
            Failure first = failures.get(0);
            return new Combined(false, Messages.get(
                MsgKey.ARCHIVE_TS_MARK_FAILURE, first.position() + 1, total, first.reason()));
        }
        if (total > 1) {
            return new Combined(true, Messages.get(MsgKey.ARCHIVE_TS_ALL_VALID, total));
        }
        return new Combined(true, null);
    }

    private static List<Object> archiveTsValues(AttributeTable ut) {
        List<Object> out = new ArrayList<>();
        if (ut == null) {
            return out;
        }
        ASN1EncodableVector all = ut.getAll(OID_ARCHIVE_TS_V3_DER);
        for (int i = 0; i < all.size(); i++) {
            Attribute a = (Attribute) all.get(i);
            ASN1Set values = a.getAttrValues();
            for (int j = 0; j < values.size(); j++) {
                out.add(values.getObjectAt(j));
            }
        }
        return out;
    }

    private static List<byte[]> nonV3AttrBlobs(AttributeTable ut) {
        List<byte[]> out = new ArrayList<>();
        if (ut == null) {
            return out;
        }
        ASN1EncodableVector all = ut.toASN1EncodableVector();
        for (int i = 0; i < all.size(); i++) {
            Attribute a = (Attribute) all.get(i);
            if (a.getAttrType().equals(OID_ARCHIVE_TS_V3_DER)) {
                continue;
            }
            byte[] typeDer = derEncoded(a.getAttrType());
            ASN1Set values = a.getAttrValues();
            for (int j = 0; j < values.size(); j++) {
                out.add(concat(typeDer, derEncoded(values.getObjectAt(j).toASN1Primitive())));
            }
        }
        return out;
    }

    private static byte[] imprintPrefix(SignerInformation si, byte[] eContentTypeDer) {
        AttributeTable at = si.getSignedAttributes();
        if (at == null) {
            return null;
        }
        Attribute mdAttr = at.get(CMSAttributes.messageDigest);
        if (mdAttr == null || mdAttr.getAttrValues().size() == 0) {
            return null;
        }
        byte[] messageDigest;
        try {
            messageDigest = ASN1OctetString.getInstance(mdAttr.getAttrValues().getObjectAt(0)).getOctets();
            var asnSi = si.toASN1Structure();
            byte[] versionDer = derEncoded(asnSi.getVersion());
            byte[] sidDer = derEncoded(asnSi.getSID());
            byte[] digestAlgDer = derEncoded(asnSi.getDigestAlgorithm());
            byte[] signedAttrsDer = signedAttrsRawBytes(at);
            byte[] sigAlgDer = derEncoded(asnSi.getDigestEncryptionAlgorithm());
            byte[] signatureDer = derEncoded(asnSi.getEncryptedDigest());
            return concat(eContentTypeDer, messageDigest, versionDer, sidDer, digestAlgDer,
                signedAttrsDer, sigAlgDer, signatureDer);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] signedAttrsRawBytes(AttributeTable signedAttrs) throws java.io.IOException {
        byte[] setEncoded = new DERSet(signedAttrs.toASN1EncodableVector()).getEncoded(ASN1Encoding.DER);
        byte[] out = setEncoded.clone();
        out[0] = (byte) 0xA0;
        return out;
    }

    private static byte[] derEncoded(org.bouncycastle.asn1.ASN1Object obj) {
        try {
            return obj.getEncoded(ASN1Encoding.DER);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<byte[]> octetStrings(Object seqElement) {
        ASN1Sequence seq = ASN1Sequence.getInstance(seqElement);
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < seq.size(); i++) {
            out.add(ASN1OctetString.getInstance(seq.getObjectAt(i)).getOctets());
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}
