package kz.edscheck.sign.cades;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes;
import kz.gov.pki.kalkan.asn1.cms.Time;
import kz.gov.pki.kalkan.asn1.ess.ESSCertIDv2;
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.jce.provider.cms.CMSAttributeTableGenerationException;
import kz.gov.pki.kalkan.jce.provider.cms.CMSAttributeTableGenerator;
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedGenerator;

import kz.edscheck.trust.KalkanJar;


public final class CadesSigner {
    private static final String OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
    private static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    private static final String PROV = "KALKAN";

    private CadesSigner() {
    }

    
    public static X509Certificate loadSignerCertificate(String p12Path, char[] password) throws Exception {
        KeyStore ks = openP12(p12Path, password);
        String alias = ks.aliases().nextElement();
        return (X509Certificate) ks.getCertificate(alias);
    }

    
    public static byte[] sign(String p12Path, char[] password, byte[] content, boolean encapsulate,
                               List<X509Certificate> chainCerts) throws Exception {
        KeyStore ks = openP12(p12Path, password);
        String alias = ks.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] certHash = sha256.digest(cert.getEncoded());

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSigner(privateKey, cert, CMSSignedGenerator.DIGEST_GOST3411_2015_512,
            new EssSignedAttrGen(certHash), null);

        List<X509Certificate> certList = new ArrayList<>();
        certList.add(cert);
        certList.addAll(chainCerts);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certList));
        gen.addCertificatesAndCRLs(certStore);

        CMSProcessableByteArray processable = new CMSProcessableByteArray(content);
        CMSSignedData signedData = gen.generate(processable, encapsulate, PROV);
        return signedData.getEncoded();
    }

    private static KeyStore openP12(String p12Path, char[] password) throws Exception {
        KalkanJar.ensureSecurityProviderRegistered();
        KeyStore ks = KeyStore.getInstance("PKCS12", PROV);
        try (InputStream in = new FileInputStream(p12Path)) {
            ks.load(in, password);
        }
        return ks;
    }

    
    private static final class EssSignedAttrGen implements CMSAttributeTableGenerator {
        private final byte[] certHash;

        EssSignedAttrGen(byte[] certHash) {
            this.certHash = certHash;
        }

        @Override
        @SuppressWarnings("unchecked")
        public AttributeTable getAttributes(Map parameters) throws CMSAttributeTableGenerationException {
            Hashtable ht = new Hashtable();

            DERObjectIdentifier contentType =
                (DERObjectIdentifier) parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE);
            Attribute aContentType = new Attribute(CMSAttributes.contentType, new DERSet(contentType));
            ht.put(aContentType.getAttrType(), aContentType);

            byte[] digest = (byte[]) parameters.get(CMSAttributeTableGenerator.DIGEST);
            Attribute aDigest = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digest)));
            ht.put(aDigest.getAttrType(), aDigest);

            Attribute aTime = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));
            ht.put(aTime.getAttrType(), aTime);

            AlgorithmIdentifier sha256Alg = new AlgorithmIdentifier(new DERObjectIdentifier(OID_SHA256));
            ESSCertIDv2 essId = new ESSCertIDv2(sha256Alg, certHash);
            SigningCertificateV2 scv2 = new SigningCertificateV2(new ESSCertIDv2[]{essId});
            Attribute aEss = new Attribute(new DERObjectIdentifier(OID_SIGNING_CERTIFICATE_V2),
                new DERSet(scv2.toASN1Object()));
            ht.put(aEss.getAttrType(), aEss);

            return new AttributeTable(ht);
        }
    }
}
