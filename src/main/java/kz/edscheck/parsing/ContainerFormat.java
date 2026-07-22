package kz.edscheck.parsing;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;

import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class ContainerFormat {
    private ContainerFormat() {
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

    private static Object readAsn1(byte[] der) {
        try {
            return new ASN1InputStream(der).readObject();
        } catch (Exception e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()), e);
        }
    }
}
