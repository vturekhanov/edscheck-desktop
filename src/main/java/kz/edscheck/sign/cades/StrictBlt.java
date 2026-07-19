package kz.edscheck.sign.cades;

import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.BERSet;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
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

public final class StrictBlt {
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final String PROV = "KALKAN";

    private StrictBlt() {
    }

    public static byte[] apply(byte[] cmsDer, int index) {
        ParsedContainer parsed = Parsing.parseContainer(cmsDer, List.of());
        if (index < 0 || index >= parsed.signers().size()) {
            throw new SignException(
                Messages.get(MsgKey.SIGN_CADES_INDEX_OUT_OF_RANGE, index, parsed.signers().size()));
        }
        ParsedSigner ps = parsed.signers().get(index);
        SignerInformation si = ps.signerInfo();
        X509Certificate signerCert = ps.signerCertRaw();
        if (signerCert == null) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_SIGNER_CERT_NOT_FOUND));
        }

        BasicOCSPResp responderBasic = Online.extractEmbeddedBasicOcsp(si.getUnsignedAttributes());
        if (responderBasic == null) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_NO_EMBEDDED_OCSP));
        }
        X509Certificate responderCert;
        try {
            X509Certificate[] certs = responderBasic.getCerts(PROV);
            if (certs.length == 0) {
                throw new SignException(Messages.get(MsgKey.STRICT_BLT_OCSP_NO_RESPONDER_CERT));
            }
            responderCert = certs[0];
        } catch (SignException e) {
            throw e;
        } catch (Exception e) {
            throw new SignException(
                Messages.get(MsgKey.STRICT_BLT_RESPONDER_CERT_READ_FAILED, e.getMessage()));
        }

        TimeStampToken tst = extractSignatureTimestamp(si);
        if (tst == null) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_NO_TSP));
        }
        X509Certificate tsaCert = firstCertificate(tst);
        if (tsaCert == null) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_TSA_CERT_NOT_FOUND));
        }

        X509Certificate tsaIssuer = Online.loadIssuerCert(tsaCert);
        if (tsaIssuer == null) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_TSA_ISSUER_NOT_FOUND,
                tsaCert.getIssuerX500Principal()));
        }
        String evpName = si.getDigestAlgOID();
        String tsaOcspUrl = Online.aiaOcspUrl(tsaCert);
        if (tsaOcspUrl == null) {
            tsaOcspUrl = CadesBltBuilder.OCSP_URL;
        }

        System.out.println("  " + Messages.get(MsgKey.STRICT_BLT_LINE_OCSP_REQUEST, tsaOcspUrl, evpName));
        BasicOCSPResp tsaBasic;
        try {
            tsaBasic = Online.requestOcsp(tsaCert, tsaIssuer, evpName, tsaOcspUrl, TIMEOUT);
        } catch (OnlineException e) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_OCSP_REQUEST_FAILED, e.getMessage()));
        }

        byte[] newTstDer = embedRevocationValuesInsideTst(tst, tsaBasic);
        TimeStampToken newTst;
        try {
            newTst = new TimeStampToken(ContentInfo.getInstance(new ASN1InputStream(newTstDer).readObject()));
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_TST_REBUILD_FAILED, e.getMessage()));
        }
        AttributeTable newOuterTable = Online.addSignatureTimestamp(si.getUnsignedAttributes(), newTst);
        SignerInformation newSi = SignerInformation.replaceUnsignedAttributes(si, newOuterTable);
        byte[] withOcspInsideTst = CadesBltBuilder.rebuildAtIndex(cmsDer, index, newSi);

        System.out.println("  " + Messages.get(MsgKey.STRICT_BLT_LINE_REVOCATION_ADDED));

        List<X509Certificate> allChainCerts = new ArrayList<>();
        allChainCerts.addAll(ChainResolver.resolveChain(signerCert));
        allChainCerts.addAll(ChainResolver.resolveChain(responderCert));
        allChainCerts.addAll(ChainResolver.resolveChain(tsaCert));

        byte[] result = CertificatesOps.appendCertificates(withOcspInsideTst, allChainCerts);
        System.out.println("  " + Messages.get(MsgKey.STRICT_BLT_LINE_CHAINS_ADDED));
        return result;
    }

    private static TimeStampToken extractSignatureTimestamp(SignerInformation si) {
        AttributeTable ut = si.getUnsignedAttributes();
        if (ut == null) {
            return null;
        }
        kz.gov.pki.kalkan.asn1.cms.Attribute tstAttr = ut.get(
            new kz.gov.pki.kalkan.asn1.DERObjectIdentifier("1.2.840.113549.1.9.16.2.14"));
        if (tstAttr == null) {
            return null;
        }
        try {
            ContentInfo tstOuter = ContentInfo.getInstance(tstAttr.getAttrValues().getObjectAt(0));
            return new TimeStampToken(tstOuter);
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_TSP_PARSE_FAILED, e.getMessage()));
        }
    }

    private static X509Certificate firstCertificate(TimeStampToken token) {
        try {
            CertStore store = token.getCertificatesAndCRLs("Collection", PROV);
            for (Certificate c : store.getCertificates(null)) {
                if (c instanceof X509Certificate x509) {
                    return x509;
                }
            }
            return null;
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_TST_CERTS_READ_FAILED, e.getMessage()));
        }
    }

    private static byte[] embedRevocationValuesInsideTst(TimeStampToken token, BasicOCSPResp basic) {
        byte[] tstDer;
        try {
            tstDer = token.getEncoded();
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.SIGN_CADES_TST_SERIALIZE_FAILED, e.getMessage()));
        }
        ContentInfo tstOuter;
        SignedData tstSignedData;
        try {
            tstOuter = ContentInfo.getInstance(new ASN1InputStream(tstDer).readObject());
            tstSignedData = SignedData.getInstance(tstOuter.getContent());
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.STRICT_BLT_TST_PARSE_FAILED, e.getMessage()));
        }
        SignerInfo tstSi = SignerInfo.getInstance(tstSignedData.getSignerInfos().getObjectAt(0));

        AttributeTable existing = tstSi.getUnauthenticatedAttributes() == null
            ? new AttributeTable(new ASN1EncodableVector())
            : new AttributeTable(tstSi.getUnauthenticatedAttributes());
        AttributeTable updated = Online.addRevocationValues(existing, basic);
        ASN1Set newUnsigned = new BERSet(updated.toASN1EncodableVector());

        SignerInfo newTstSi = new SignerInfo(tstSi.getSID(), tstSi.getDigestAlgorithm(),
            tstSi.getAuthenticatedAttributes(), tstSi.getDigestEncryptionAlgorithm(),
            tstSi.getEncryptedDigest(), newUnsigned);

        ASN1EncodableVector signerInfoVec = new ASN1EncodableVector();
        signerInfoVec.add(newTstSi);
        SignedData newTstSignedData = new SignedData(
            tstSignedData.getDigestAlgorithms(), tstSignedData.getEncapContentInfo(),
            tstSignedData.getCertificates(), tstSignedData.getCRLs(), new BERSet(signerInfoVec));
        ContentInfo newTstOuter = new ContentInfo(
            kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers.signedData, newTstSignedData);
        return newTstOuter.getDEREncoded();
    }
}
