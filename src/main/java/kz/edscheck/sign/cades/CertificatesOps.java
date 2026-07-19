package kz.edscheck.sign.cades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
import kz.gov.pki.kalkan.asn1.x509.X509CertificateStructure;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class CertificatesOps {

    private static final String OID_ARCHIVE_TIMESTAMP_V3 = "0.4.0.1733.2.4";

    private CertificatesOps() {
    }

    public static byte[] appendCertificates(byte[] cmsDer, List<X509Certificate> newCerts) {
        ContentInfo outer;
        SignedData signedData;
        try {
            outer = ContentInfo.getInstance(new ASN1InputStream(cmsDer).readObject());
            signedData = SignedData.getInstance(outer.getContent());
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()));
        }

        ASN1Set signerInfos = signedData.getSignerInfos();
        List<String> archived = new ArrayList<>();
        for (int i = 0; i < signerInfos.size(); i++) {
            if (hasArchiveTimestamp(SignerInfo.getInstance(signerInfos.getObjectAt(i)))) {
                archived.add(String.valueOf(i));
            }
        }
        if (!archived.isEmpty()) {
            throw new SignException(
                Messages.get(MsgKey.CERTIFICATES_OPS_ARCHIVE_GUARD, String.join(", #", archived)));
        }

        Set<String> existingFingerprints = new HashSet<>();
        ASN1Set certs = signedData.getCertificates();
        if (certs != null) {
            for (int i = 0; i < certs.size(); i++) {
                existingFingerprints.add(fingerprint(certs.getObjectAt(i)));
            }
        }

        List<X509CertificateStructure> toAdd = new ArrayList<>();
        for (X509Certificate cert : newCerts) {
            byte[] der;
            try {
                der = cert.getEncoded();
            } catch (Exception e) {
                throw new SignException(Messages.get(MsgKey.CERTIFICATES_OPS_CERT_ENCODE_FAILED, e.getMessage()));
            }
            if (existingFingerprints.add(Base64.getEncoder().encodeToString(der))) {
                try {
                    toAdd.add(X509CertificateStructure.getInstance(new ASN1InputStream(der).readObject()));
                } catch (Exception e) {
                    throw new SignException(Messages.get(MsgKey.CERTIFICATES_OPS_CERT_PARSE_FAILED, e.getMessage()));
                }
            }
        }
        if (toAdd.isEmpty()) {
            return cmsDer;
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (certs != null) {
            for (int i = 0; i < certs.size(); i++) {
                vec.add(certs.getObjectAt(i));
            }
        }
        for (X509CertificateStructure cs : toAdd) {
            vec.add(cs);
        }

        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            new DERSet(vec), signedData.getCRLs(), signedData.getSignerInfos());
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return newOuter.getDEREncoded();
    }

    static boolean hasArchiveTimestamp(SignerInfo si) {
        ASN1Set unsigned = si.getUnauthenticatedAttributes();
        if (unsigned == null) {
            return false;
        }
        for (int i = 0; i < unsigned.size(); i++) {
            Attribute attr = Attribute.getInstance(unsigned.getObjectAt(i));
            if (attr.getAttrType().getId().equals(OID_ARCHIVE_TIMESTAMP_V3)) {
                return true;
            }
        }
        return false;
    }

    private static String fingerprint(Object certObj) {
        try {
            X509CertificateStructure cs = X509CertificateStructure.getInstance(certObj);
            return Base64.getEncoder().encodeToString(cs.getDEREncoded());
        } catch (Exception e) {
            return "";
        }
    }
}
