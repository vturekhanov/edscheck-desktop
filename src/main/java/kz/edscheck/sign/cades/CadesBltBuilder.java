package kz.edscheck.sign.cades;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.online.Online;
import kz.edscheck.online.OnlineException;
import kz.edscheck.parsing.ParsedContainer;
import kz.edscheck.parsing.ParsedSigner;
import kz.edscheck.parsing.Parsing;
import kz.edscheck.trust.DigestAlgorithms;

public final class CadesBltBuilder {

    public static final String OCSP_URL = "http://ocsp.pki.gov.kz/";

    public static final String TSA_URL = "http://tsp.pki.gov.kz/";

    public static final String TSA_REQ_POLICY = "1.2.398.3.3.2.6.4";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private CadesBltBuilder() {
    }

    public static X509Certificate resolveIssuer(X509Certificate subject) {
        X509Certificate issuer = Online.loadIssuerCert(subject);
        if (issuer == null) {
            throw new SignException(
                Messages.get(MsgKey.CADES_BLT_ISSUER_NOT_FOUND, subject.getIssuerX500Principal()));
        }
        return issuer;
    }

    public static byte[] augmentWithOcspAndTsa(byte[] bareCms) {
        return augmentWithOcspAndTsa(bareCms, 0);
    }

    public static byte[] augmentWithOcspAndTsa(byte[] bareCms, int index) {
        ParsedContainer parsed = Parsing.parseContainer(bareCms, List.of());
        if (index < 0 || index >= parsed.signers().size()) {
            throw new SignException(
                Messages.get(MsgKey.SIGN_CADES_INDEX_OUT_OF_RANGE, index, parsed.signers().size()));
        }
        ParsedSigner ps = parsed.signers().get(index);
        X509Certificate subject = ps.signerCertRaw();
        if (subject == null) {
            throw new SignException(Messages.get(MsgKey.CADES_BLT_SIGNER_CERT_NOT_FOUND));
        }
        X509Certificate issuer = resolveIssuer(subject);

        SignerInformation si = ps.signerInfo();
        String digestOid = si.getDigestAlgOID();

        System.out.println("  " + Messages.get(MsgKey.CADES_BLT_LINE_TSA_REQUEST, TSA_URL));
        TimeStampToken token = requestTsaForSignature(si, TSA_URL, TSA_REQ_POLICY);
        si = SignerInformation.replaceUnsignedAttributes(
            si, Online.addSignatureTimestamp(si.getUnsignedAttributes(), token));

        System.out.println("  " + Messages.get(MsgKey.CADES_BLT_LINE_OCSP_REQUEST, OCSP_URL, digestOid));
        BasicOCSPResp basic;
        try {
            basic = Online.requestOcsp(subject, issuer, digestOid, OCSP_URL, TIMEOUT);
        } catch (OnlineException e) {
            throw new SignException(Messages.get(MsgKey.ONLINE_OCSP_REQUEST_FAILED, e.getMessage()));
        }
        si = SignerInformation.replaceUnsignedAttributes(
            si, Online.addRevocationValues(si.getUnsignedAttributes(), basic));

        return rebuildAtIndex(bareCms, index, si);
    }

    static TimeStampToken requestTsaForSignature(SignerInformation si, String tsaUrl, String reqPolicy) {
        String digestOid = si.getDigestAlgOID();
        String jceName = DigestAlgorithms.jceName(digestOid);
        if (jceName == null) {
            throw new SignException(Messages.get(MsgKey.ONLINE_UNKNOWN_DIGEST_ALG, digestOid));
        }
        byte[] sigValue = si.getSignature();
        if (sigValue == null) {
            throw new SignException(Messages.get(MsgKey.ONLINE_SIGNATURE_VALUE_MISSING));
        }
        byte[] imprint;
        try {
            imprint = MessageDigest.getInstance(jceName, "KALKAN").digest(sigValue);
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.ONLINE_IMPRINT_COMPUTE_FAILED, e.getMessage()));
        }
        try {
            return Online.requestTsa(imprint, digestOid, tsaUrl, reqPolicy, TIMEOUT);
        } catch (OnlineException e) {
            throw new SignException(Messages.get(MsgKey.ONLINE_TSA_REQUEST_FAILED, e.getMessage()));
        }
    }

    static byte[] rebuildAtIndex(byte[] cmsDer, int index, SignerInformation updatedSi) {
        return rebuildAtIndices(cmsDer, Map.of(index, updatedSi));
    }

    static byte[] rebuildAtIndices(byte[] cmsDer, Map<Integer, SignerInformation> updates) {
        Object asn1;
        try {
            asn1 = new ASN1InputStream(cmsDer).readObject();
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()));
        }
        ContentInfo outer = ContentInfo.getInstance(asn1);
        SignedData signedData = SignedData.getInstance(outer.getContent());

        Map<Integer, kz.gov.pki.kalkan.asn1.cms.SignerInfo> rawUpdates = new java.util.LinkedHashMap<>();
        for (Map.Entry<Integer, SignerInformation> e : updates.entrySet()) {
            rawUpdates.put(e.getKey(), e.getValue().toSignerInfo());
        }
        ASN1Set newSignerInfos = Online.mergeSignerInfos(signedData.getSignerInfos(), rawUpdates);
        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), newSignerInfos);
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return newOuter.getDEREncoded();
    }
}
