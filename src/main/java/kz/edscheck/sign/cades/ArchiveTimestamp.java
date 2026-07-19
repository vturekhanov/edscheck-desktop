package kz.edscheck.sign.cades;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.BERSet;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.DERTaggedObject;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.asn1.x509.X509CertificateStructure;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

import kz.edscheck.domain.Environment;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.TrustMaterial;
import kz.edscheck.domain.Verdict;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.engine.VerificationEngine;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.online.Online;
import kz.edscheck.online.OnlineException;
import kz.edscheck.provider.VerificationProvider;
import kz.edscheck.provider.kalkan.KalkanProvider;
import kz.edscheck.trust.DigestAlgorithms;
import kz.edscheck.trust.KalkanJar;
import kz.edscheck.trust.KalkanJarException;
import kz.edscheck.trust.ManifestTrust;

public final class ArchiveTimestamp {

    static final String OID_ATS_HASH_INDEX_V3 = "0.4.0.19122.1.5";
    static final String OID_ARCHIVE_TIMESTAMP_V3 = "0.4.0.1733.2.4";
    private static final String OID_SIGNATURE_TS_TOKEN = "1.2.840.113549.1.9.16.2.14";
    private static final String OID_REVOCATION_VALUES = "1.2.840.113549.1.9.16.2.24";
    private static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private ArchiveTimestamp() {
    }

    public static AttrOps.Result addArchiveTimestamp(
            byte[] cmsDer, String tsaUrl, String reqPolicy, String displayPath, SignerSelector selector) {
        ContentInfo outer = parseOuter(cmsDer);
        SignedData signedData = SignedData.getInstance(outer.getContent());
        ASN1Set signerInfos = signedData.getSignerInfos();
        List<Integer> indices = selector.resolve(signerInfos.size());

        requireArchiveGuards(cmsDer, displayPath, signerInfos, indices);

        boolean multi = indices.size() > 1;
        Map<Integer, SignerInfo> updates = new LinkedHashMap<>();
        List<String> messages = new ArrayList<>();
        for (int idx : indices) {
            String prefix = multi ? "#" + idx + ": " : "";
            SignerInfo si = SignerInfo.getInstance(signerInfos.getObjectAt(idx));

            String digestOid = si.getDigestAlgorithm().getObjectId().getId();
            String jceName = DigestAlgorithms.jceName(digestOid);
            if (jceName == null) {
                throw new SignException(Messages.get(MsgKey.ARCHIVE_STAMP_UNKNOWN_DIGEST_ALGO, prefix, digestOid));
            }

            List<byte[]> certHashes = hashCertificates(signedData.getCertificates(), jceName);
            List<byte[]> crlHashes = List.of(); 
            List<byte[]> attrHashes = hashUnsignedAttrs(si.getUnauthenticatedAttributes(), jceName);
            byte[] atsHashIndexDer = buildAtsHashIndexV3(digestOid, certHashes, crlHashes, attrHashes);

            byte[] imprint = computeImprint(signedData, si, atsHashIndexDer, jceName);

            TimeStampToken token;
            try {
                token = Online.requestTsa(imprint, digestOid, tsaUrl, reqPolicy, TIMEOUT);
            } catch (OnlineException e) {
                throw new SignException(
                    Messages.get(MsgKey.ARCHIVE_STAMP_TSA_REQUEST_FAILED, prefix, e.getMessage()));
            }
            byte[] augmentedTstDer = embedAtsHashIndex(token, atsHashIndexDer);

            int existing = countArchiveTimestamps(si.getUnauthenticatedAttributes());
            ASN1Set newUnsigned = appendAttribute(si.getUnauthenticatedAttributes(),
                new Attribute(new DERObjectIdentifier(OID_ARCHIVE_TIMESTAMP_V3),
                    new DERSet(parseAny(augmentedTstDer))));
            SignerInfo newSi = new SignerInfo(si.getSID(), si.getDigestAlgorithm(), si.getAuthenticatedAttributes(),
                si.getDigestEncryptionAlgorithm(), si.getEncryptedDigest(), newUnsigned);
            updates.put(idx, newSi);
            messages.add(Messages.get(MsgKey.ARCHIVE_STAMP_ADDED, prefix, existing, existing + 1));
        }

        ASN1Set newSignerInfos = Online.mergeSignerInfos(signerInfos, updates);
        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), newSignerInfos);
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return new AttrOps.Result(newOuter.getDEREncoded(), true, messages);
    }

    private static void requireArchiveGuards(
            byte[] cmsDer, String displayPath, ASN1Set signerInfos, List<Integer> indices) {
        Environment env = Environment.PROD;
        List<String> roots = ManifestTrust.trustedCerts("auto", env.jsonValue());
        TrustMaterial trust = new TrustMaterial(roots, List.of());
        VerificationRequest request = new VerificationRequest(
            displayPath, "auto", env, trust, null, java.util.Map.of(), false);

        VerificationProvider provider;
        try {
            KalkanJar.resolveAndVerify();
            provider = new KalkanProvider();
        } catch (KalkanJarException e) {
            throw new SignException(Messages.get(MsgKey.ARCHIVE_STAMP_PROVIDER_PREPARE_FAILED, e.getMessage()));
        }
        VerificationEngine engine = new VerificationEngine(provider);

        SignedContainer result;
        try {
            result = engine.verify(request, cmsDer);
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.ARCHIVE_STAMP_VERIFICATION_FAILED, e.getMessage()));
        }
        Map<Integer, Verdict> verdictByIndex = new java.util.HashMap<>();
        for (kz.edscheck.domain.Signature s : result.signatures()) {
            verdictByIndex.put(s.index(), s.verdict());
        }

        List<String> invalid = new ArrayList<>();
        List<String> notReady = new ArrayList<>();
        for (int idx : indices) {
            if (verdictByIndex.get(idx) == Verdict.INVALID) {
                invalid.add(String.valueOf(idx));
            }
            if (!isReadyForArchive(SignerInfo.getInstance(signerInfos.getObjectAt(idx)))) {
                notReady.add(String.valueOf(idx));
            }
        }
        List<String> problems = new ArrayList<>();
        if (!invalid.isEmpty()) {
            problems.add(Messages.get(MsgKey.ARCHIVE_STAMP_SIGNATURES_INVALID, String.join(", #", invalid)));
        }
        if (!notReady.isEmpty()) {
            problems.add(Messages.get(MsgKey.ARCHIVE_STAMP_SIGNERS_NOT_READY, String.join(", #", notReady)));
        }
        if (!problems.isEmpty()) {
            throw new SignException(String.join("; ", problems));
        }
    }

    private static boolean isReadyForArchive(SignerInfo si) {
        ASN1Set unsigned = si.getUnauthenticatedAttributes();
        boolean hasTst = false;
        boolean hasRevocation = false;
        if (unsigned != null) {
            for (int i = 0; i < unsigned.size(); i++) {
                String oid = Attribute.getInstance(unsigned.getObjectAt(i)).getAttrType().getId();
                hasTst |= oid.equals(OID_SIGNATURE_TS_TOKEN);
                hasRevocation |= oid.equals(OID_REVOCATION_VALUES);
            }
        }
        return hasTst && hasRevocation;
    }

    static List<byte[]> hashCertificates(ASN1Set certs, String jceName) {
        List<byte[]> hashes = new ArrayList<>();
        if (certs == null) {
            return hashes;
        }
        for (int i = 0; i < certs.size(); i++) {
            byte[] der = X509CertificateStructure.getInstance(certs.getObjectAt(i)).getDEREncoded();
            hashes.add(digest(der, jceName));
        }
        return hashes;
    }

    static List<byte[]> hashUnsignedAttrs(ASN1Set unsignedAttrs, String jceName) {
        List<byte[]> hashes = new ArrayList<>();
        if (unsignedAttrs == null) {
            return hashes;
        }
        for (int i = 0; i < unsignedAttrs.size(); i++) {
            Attribute attr = Attribute.getInstance(unsignedAttrs.getObjectAt(i));
            byte[] typeDer = derBytes(attr.getAttrType());
            ASN1Set values = attr.getAttrValues();
            for (int j = 0; j < values.size(); j++) {
                byte[] valueDer = derBytes(values.getObjectAt(j));
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                try {
                    buf.write(typeDer);
                    buf.write(valueDer);
                } catch (java.io.IOException e) {
                    throw new SignException(e.getMessage(), e);
                }
                hashes.add(digest(buf.toByteArray(), jceName));
            }
        }
        return hashes;
    }

    static byte[] buildAtsHashIndexV3(String hashAlgOid, List<byte[]> certHashes, List<byte[]> crlHashes,
                                       List<byte[]> attrHashes) {

        AlgorithmIdentifier algId = new AlgorithmIdentifier(new DERObjectIdentifier(hashAlgOid), null);
        ASN1EncodableVector body = new ASN1EncodableVector();
        body.add(algId);
        body.add(seqOfOctetStrings(certHashes));
        body.add(seqOfOctetStrings(crlHashes));
        body.add(seqOfOctetStrings(attrHashes));
        return new DERSequence(body).getDEREncoded();
    }

    private static DERSequence seqOfOctetStrings(List<byte[]> hashes) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (byte[] h : hashes) {
            v.add(new DEROctetString(h));
        }
        return new DERSequence(v);
    }

    static byte[] computeImprint(SignedData signedData, SignerInfo si, byte[] atsHashIndexDer, String jceName) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            buf.write(derBytes(signedData.getEncapContentInfo().getContentType()));
            buf.write(messageDigestValue(si.getAuthenticatedAttributes()));
            buf.write(derBytes(si.getVersion()));
            buf.write(derBytes(si.getSID()));
            buf.write(derBytes(si.getDigestAlgorithm()));
            buf.write(new DERTaggedObject(false, 0, si.getAuthenticatedAttributes()).getDEREncoded());
            buf.write(derBytes(si.getDigestEncryptionAlgorithm()));
            buf.write(derBytes(si.getEncryptedDigest()));
            buf.write(atsHashIndexDer);
        } catch (java.io.IOException e) {
            throw new SignException(e.getMessage(), e);
        }
        return digest(buf.toByteArray(), jceName);
    }

    private static byte[] messageDigestValue(ASN1Set signedAttrs) {
        for (int i = 0; i < signedAttrs.size(); i++) {
            Attribute attr = Attribute.getInstance(signedAttrs.getObjectAt(i));
            if (attr.getAttrType().getId().equals(OID_MESSAGE_DIGEST)) {
                ASN1OctetString os = ASN1OctetString.getInstance(attr.getAttrValues().getObjectAt(0));
                return os.getOctets();
            }
        }
        throw new SignException(Messages.get(MsgKey.ARCHIVE_STAMP_MESSAGE_DIGEST_ATTR_MISSING));
    }

    private static byte[] derBytes(DEREncodable obj) {
        return obj.getDERObject().getDEREncoded();
    }

    private static byte[] digest(byte[] data, String jceName) {
        try {
            return MessageDigest.getInstance(jceName, "KALKAN").digest(data);
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.ARCHIVE_STAMP_HASH_COMPUTE_FAILED, e.getMessage()), e);
        }
    }

    private static byte[] embedAtsHashIndex(TimeStampToken token, byte[] atsHashIndexDer) {
        byte[] tstDer;
        try {
            tstDer = token.getEncoded();
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.SIGN_CADES_TST_SERIALIZE_FAILED, e.getMessage()));
        }
        ContentInfo tstOuter = parseOuter(tstDer);
        SignedData tstSignedData = SignedData.getInstance(tstOuter.getContent());
        SignerInfo tstSi = SignerInfo.getInstance(tstSignedData.getSignerInfos().getObjectAt(0));

        Attribute atsAttr = new Attribute(new DERObjectIdentifier(OID_ATS_HASH_INDEX_V3),
            new DERSet(parseAny(atsHashIndexDer)));
        ASN1Set newUnsigned = replaceOrAdd(tstSi.getUnauthenticatedAttributes(), atsAttr);

        SignerInfo newTstSi = new SignerInfo(tstSi.getSID(), tstSi.getDigestAlgorithm(),
            tstSi.getAuthenticatedAttributes(), tstSi.getDigestEncryptionAlgorithm(),
            tstSi.getEncryptedDigest(), newUnsigned);
        return rebuildWithSigner(tstSignedData, newTstSi);
    }

    public static AttrOps.Result stripArchive(byte[] cmsDer, boolean all, SignerSelector selector) {
        ContentInfo outer = parseOuter(cmsDer);
        SignedData signedData = SignedData.getInstance(outer.getContent());
        ASN1Set signerInfos = signedData.getSignerInfos();
        List<Integer> indices = selector.resolve(signerInfos.size());
        boolean multi = indices.size() > 1;

        Map<Integer, SignerInfo> updates = new LinkedHashMap<>();
        List<String> messages = new ArrayList<>();
        for (int idx : indices) {
            String prefix = multi ? "#" + idx + ": " : "";
            SignerInfo si = SignerInfo.getInstance(signerInfos.getObjectAt(idx));
            ASN1Set unsigned = si.getUnauthenticatedAttributes();
            int existing = countArchiveTimestamps(unsigned);
            if (existing == 0) {
                messages.add(Messages.get(MsgKey.ARCHIVE_STAMP_NONE_TO_STRIP, prefix));
                continue;
            }

            int lastIdx = -1;
            for (int i = 0; i < unsigned.size(); i++) {
                if (Attribute.getInstance(unsigned.getObjectAt(i)).getAttrType().getId()
                        .equals(OID_ARCHIVE_TIMESTAMP_V3)) {
                    lastIdx = i;
                }
            }
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (int i = 0; i < unsigned.size(); i++) {
                boolean isArchive = Attribute.getInstance(unsigned.getObjectAt(i)).getAttrType().getId()
                    .equals(OID_ARCHIVE_TIMESTAMP_V3);
                if ((all && isArchive) || (!all && i == lastIdx)) {
                    continue;
                }
                vec.add(unsigned.getObjectAt(i));
            }
            ASN1Set newUnsigned = vec.size() == 0 ? null : new BERSet(vec);
            SignerInfo newSi = new SignerInfo(si.getSID(), si.getDigestAlgorithm(), si.getAuthenticatedAttributes(),
                si.getDigestEncryptionAlgorithm(), si.getEncryptedDigest(), newUnsigned);
            updates.put(idx, newSi);
            messages.add(all
                ? Messages.get(MsgKey.ARCHIVE_STAMP_STRIPPED_ALL, prefix, existing)
                : Messages.get(MsgKey.ARCHIVE_STAMP_STRIPPED_LAST, prefix, existing, existing - 1));
        }

        if (updates.isEmpty()) {
            return new AttrOps.Result(cmsDer, false, messages);
        }
        ASN1Set newSignerInfos = Online.mergeSignerInfos(signerInfos, updates);
        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), newSignerInfos);
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return new AttrOps.Result(newOuter.getDEREncoded(), true, messages);
    }

    private static int countArchiveTimestamps(ASN1Set unsignedAttrs) {
        if (unsignedAttrs == null) {
            return 0;
        }
        int count = 0;
        for (int i = 0; i < unsignedAttrs.size(); i++) {
            if (Attribute.getInstance(unsignedAttrs.getObjectAt(i)).getAttrType().getId()
                    .equals(OID_ARCHIVE_TIMESTAMP_V3)) {
                count++;
            }
        }
        return count;
    }

    private static ASN1Set replaceOrAdd(ASN1Set existing, Attribute newAttr) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (existing != null) {
            for (int i = 0; i < existing.size(); i++) {
                Attribute a = Attribute.getInstance(existing.getObjectAt(i));
                if (!a.getAttrType().equals(newAttr.getAttrType())) {
                    vec.add(a);
                }
            }
        }
        vec.add(newAttr);
        return new BERSet(vec);
    }

    private static ASN1Set appendAttribute(ASN1Set existing, Attribute newAttr) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (existing != null) {
            for (int i = 0; i < existing.size(); i++) {
                vec.add(existing.getObjectAt(i));
            }
        }
        vec.add(newAttr);
        return new BERSet(vec);
    }

    private static byte[] rebuildWithSigner(SignedData signedData, SignerInfo newSi) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(newSi);
        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), new DERSet(vec));
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return newOuter.getDEREncoded();
    }

    private static ContentInfo parseOuter(byte[] der) {
        try {
            return ContentInfo.getInstance(new ASN1InputStream(der).readObject());
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()));
        }
    }

    private static kz.gov.pki.kalkan.asn1.DERObject parseAny(byte[] der) {
        try {
            return new ASN1InputStream(der).readObject();
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.ARCHIVE_STAMP_ASN1_PARSE_FAILED, e.getMessage()));
        }
    }
}
