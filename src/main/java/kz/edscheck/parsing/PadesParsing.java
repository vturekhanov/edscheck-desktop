package kz.edscheck.parsing;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponse;

import kz.edscheck.domain.Encoding;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.ArchiveTimestampInfo;
import kz.edscheck.pades.PadesCoverage;
import kz.edscheck.pades.PadesDssMaterial;
import kz.edscheck.pades.PadesSignatureInput;
import kz.edscheck.pades.PadesSignatureObject;
import kz.edscheck.trust.ActiveBackend;

public final class PadesParsing {

    private static final ASN1ObjectIdentifier OID_RI_OCSP_RESPONSE =
        new ASN1ObjectIdentifier("1.3.6.1.5.5.7.16.2");

    private static final int TAG_REVOCATION_INFO_OTHER = 1;

    private PadesParsing() {
    }

    public static ParsedContainer toParsedContainer(PadesSignatureInput input, List<X509Certificate> trust) {
        PadesSignatureObject object = input.object();
        if (!PadesSignatureObject.SUBFILTER_CADES_DETACHED.equals(object.subFilter())) {
            throw new ContainerException(Messages.get(MsgKey.PADES_SUBFILTER_UNSUPPORTED,
                object.subFilter() != null ? object.subFilter() : Messages.get(MsgKey.PADES_SUBFILTER_ABSENT)));
        }

        PadesDssMaterial dss = input.dss();
        List<X509Certificate> dssCerts = parseCertificates(dss);
        List<X509Certificate> extra = new ArrayList<>(trust);
        extra.addAll(dssCerts);

        ParsedContainer parsed = Parsing.parseByteRange(
            stripContentsPadding(object.contents()), extra, input.fileBytes(), object.byteRange());
        if (parsed.signers().size() != 1) {
            throw new ContainerException(Messages.get(MsgKey.PADES_MULTIPLE_SIGNER_INFOS));
        }

        ParsedSigner signer = parsed.signers().get(0);
        List<String> missingAttrs = Parsing.missingMandatoryPadesAttrs(
            signer.signerInfo().getSignedAttributes(),
            object.signingDate() != null && !object.signingDate().isEmpty());

        List<X509Certificate> containerCerts = new ArrayList<>(parsed.containerCerts());
        for (X509Certificate cert : dssCerts) {
            if (!containerCerts.contains(cert)) {
                containerCerts.add(cert);
            }
        }

        List<byte[]> crlBlobs = new ArrayList<>(parsed.crlBlobs());
        crlBlobs.addAll(revocationBlobs(dss));

        List<ArchiveTs.ParsedArchiveTimestamp> marks = archiveMarks(input);
        Instant lastGenTime = marks.isEmpty() ? null : marks.get(marks.size() - 1).genTime;

        return new ParsedContainer(
            Encoding.DER, parsed.cadesLevel(),
            List.of(Parsing.withIndexAndMissingAttrs(
                signer, input.index(), missingAttrs, marks,
                new ArchiveTimestampInfo(marks.size(), 0, lastGenTime))),
            containerCerts, crlBlobs);
    }

    private static List<ArchiveTs.ParsedArchiveTimestamp> archiveMarks(PadesSignatureInput input) {
        List<PadesSignatureObject> chain = PadesCoverage.coveringChain(input.object(), input.allObjects());
        List<ArchiveTs.ParsedArchiveTimestamp> marks = new ArrayList<>(chain.size());
        for (int position = 0; position < chain.size(); position++) {
            PadesSignatureObject mark = chain.get(position);
            ArchiveTs.ParsedArchiveTimestamp parsedMark =
                ArchiveTs.parsePadesMark(position, stripContentsPadding(mark.contents()), null);
            if (parsedMark.parseError == null) {
                parsedMark.precomputedImprint = Parsing.byteRangeDigest(
                    input.fileBytes(), mark.byteRange(), parsedMark.imprintAlgOid);
            }
            marks.add(parsedMark);
        }
        return marks;
    }

    static byte[] stripContentsPadding(byte[] contents) {
        if (contents.length < 2) {
            return contents;
        }
        int pos = 1; 
        int first = contents[pos++] & 0xFF;
        int length;
        if (first == 0x80) {
            return contents; 
        }
        if (first < 0x80) {
            length = first;
        } else {
            int octets = first & 0x7F;
            if (octets == 0 || octets > 4 || pos + octets > contents.length) {
                return contents;
            }
            length = 0;
            for (int i = 0; i < octets; i++) {
                length = (length << 8) | (contents[pos++] & 0xFF);
            }
            if (length < 0) {
                return contents;
            }
        }
        long total = (long) pos + length;
        if (total <= 0 || total > contents.length) {
            return contents;
        }
        return java.util.Arrays.copyOf(contents, (int) total);
    }

    private static List<X509Certificate> parseCertificates(PadesDssMaterial dss) {
        if (dss == null || dss.certs().isEmpty()) {
            return List.of();
        }
        List<X509Certificate> certs = new ArrayList<>(dss.certs().size());
        try {
            CertificateFactory cf =
                CertificateFactory.getInstance("X.509", ActiveBackend.current().jceProviderName());
            for (byte[] der : dss.certs()) {
                try {
                    certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
                } catch (Exception ignored) {

                }
            }
        } catch (Exception ignored) {

        }
        return certs;
    }

    private static List<byte[]> revocationBlobs(PadesDssMaterial dss) {
        if (dss == null) {
            return List.of();
        }
        List<byte[]> blobs = new ArrayList<>(dss.crls().size() + dss.ocsps().size());
        blobs.addAll(dss.crls());
        for (byte[] der : dss.ocsps()) {
            byte[] wrapped = wrapOcspResponse(der);
            if (wrapped != null) {
                blobs.add(wrapped);
            }
        }
        return blobs;
    }

    private static byte[] wrapOcspResponse(byte[] der) {
        try {
            ASN1Primitive parsed = new ASN1InputStream(der).readObject();
            OCSPResponse response = OCSPResponse.getInstance(parsed);
            ASN1Sequence other = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                OID_RI_OCSP_RESPONSE, response});
            return new DERTaggedObject(false, TAG_REVOCATION_INFO_OTHER, other).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            return null;
        }
    }
}
