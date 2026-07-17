package kz.edscheck.sign.cades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.BERSet;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.online.Online;


public final class CoSign {
    
    
    
    
    
    private static final String OID_DATA = "1.2.840.113549.1.7.1";

    private CoSign() {
    }

    
    public static boolean looksLikeCades(byte[] bytes) {
        try {
            ContentInfo outer = ContentInfo.getInstance(new ASN1InputStream(bytes).readObject());
            if (!CMSObjectIdentifiers.signedData.equals(outer.getContentType())) {
                return false;
            }
            SignedData signedData = SignedData.getInstance(outer.getContent());
            return signedData.getSignerInfos().size() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    
    public static boolean isAttached(byte[] cmsDer) {
        ContentInfo outer = ContentInfo.getInstance(readAsn1(cmsDer));
        SignedData signedData = SignedData.getInstance(outer.getContent());
        return signedData.getEncapContentInfo().getContent() != null;
    }

    public record Result(byte[] bytes, int newIndex) {
    }

    
    public static Result addSigner(byte[] existingCmsDer, byte[] document, String p12Path, char[] password,
                                    List<X509Certificate> chainCerts) throws Exception {
        ContentInfo outer = ContentInfo.getInstance(readAsn1(existingCmsDer));
        SignedData signedData = SignedData.getInstance(outer.getContent());
        ASN1Set existingSigners = signedData.getSignerInfos();
        requireNoArchiveTimestampAnywhere(existingSigners);

        String eContentType = signedData.getEncapContentInfo().getContentType().getId();
        if (!OID_DATA.equals(eContentType)) {
            throw new SignException(
                Messages.get(MsgKey.CO_SIGN_UNSUPPORTED_CONTENT_TYPE, OID_DATA, eContentType));
        }

        ContentInfo encap = signedData.getEncapContentInfo();
        byte[] content;
        boolean encapsulate;
        if (encap.getContent() != null) {
            content = ASN1OctetString.getInstance(encap.getContent()).getOctets();
            encapsulate = true;
        } else {
            if (document == null) {
                throw new SignException(Messages.get(MsgKey.CO_SIGN_DETACHED_NEEDS_DOCUMENT));
            }
            content = document;
            encapsulate = false;
        }

        X509Certificate signerCert = CadesSigner.loadSignerCertificate(p12Path, password);
        byte[] freshCms = CadesSigner.sign(p12Path, password, content, encapsulate, List.of());
        ContentInfo freshOuter = ContentInfo.getInstance(readAsn1(freshCms));
        SignedData freshSd = SignedData.getInstance(freshOuter.getContent());
        SignerInfo newSi = SignerInfo.getInstance(freshSd.getSignerInfos().getObjectAt(0));

        ASN1Set mergedDigestAlgs = unionAlgorithmIdentifiers(
            signedData.getDigestAlgorithms(), freshSd.getDigestAlgorithms());
        int newIndex = existingSigners.size();
        ASN1Set mergedSigners = Online.mergeSignerInfos(existingSigners, Map.of(newIndex, newSi));

        SignedData merged = new SignedData(mergedDigestAlgs, signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), mergedSigners);
        ContentInfo mergedOuter = new ContentInfo(CMSObjectIdentifiers.signedData, merged);
        byte[] mergedDer = mergedOuter.getDEREncoded();

        List<X509Certificate> newCerts = new ArrayList<>();
        newCerts.add(signerCert);
        newCerts.addAll(chainCerts);
        byte[] withCerts = CertificatesOps.appendCertificates(mergedDer, newCerts);
        return new Result(withCerts, newIndex);
    }

    private static void requireNoArchiveTimestampAnywhere(ASN1Set signerInfos) {
        List<String> archived = new ArrayList<>();
        for (int i = 0; i < signerInfos.size(); i++) {
            if (CertificatesOps.hasArchiveTimestamp(SignerInfo.getInstance(signerInfos.getObjectAt(i)))) {
                archived.add(String.valueOf(i));
            }
        }
        if (!archived.isEmpty()) {
            throw new SignException(Messages.get(MsgKey.CO_SIGN_ARCHIVE_GUARD, String.join(", #", archived)));
        }
    }

    private static ASN1Set unionAlgorithmIdentifiers(ASN1Set existing, ASN1Set fresh) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < existing.size(); i++) {
            AlgorithmIdentifier alg = AlgorithmIdentifier.getInstance(existing.getObjectAt(i));
            if (seen.add(alg.getObjectId().getId())) {
                vec.add(alg);
            }
        }
        for (int i = 0; i < fresh.size(); i++) {
            AlgorithmIdentifier alg = AlgorithmIdentifier.getInstance(fresh.getObjectAt(i));
            if (seen.add(alg.getObjectId().getId())) {
                vec.add(alg);
            }
        }
        return new BERSet(vec);
    }

    private static Object readAsn1(byte[] der) {
        try {
            return new ASN1InputStream(der).readObject();
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()));
        }
    }
}
