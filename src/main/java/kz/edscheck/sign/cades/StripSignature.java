package kz.edscheck.sign.cades;

import java.util.List;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.BERSet;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class StripSignature {
    private StripSignature() {
    }

    public static AttrOps.Result strip(byte[] cmsDer, int index) {
        ContentInfo outer = parseOuter(cmsDer);
        SignedData signedData = SignedData.getInstance(outer.getContent());
        ASN1Set signerInfos = signedData.getSignerInfos();
        int n = signerInfos.size();

        if (index < 0 || index >= n) {
            throw new SignException(Messages.get(MsgKey.SIGN_CADES_INDEX_OUT_OF_RANGE, index, n));
        }
        if (n <= 1) {
            return new AttrOps.Result(cmsDer, false, List.of(Messages.get(MsgKey.STRIP_SIGNATURE_ONLY_ONE)));
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i < n; i++) {
            if (i != index) {
                vec.add(signerInfos.getObjectAt(i));
            }
        }

        ASN1Set newSignerInfos = new BERSet(vec);
        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), newSignerInfos);
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        String message = Messages.get(MsgKey.STRIP_SIGNATURE_REMOVED, index, n - 1);
        return new AttrOps.Result(newOuter.getDEREncoded(), true, List.of(message));
    }

    private static ContentInfo parseOuter(byte[] der) {
        try {
            return ContentInfo.getInstance(new ASN1InputStream(der).readObject());
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()));
        }
    }
}
