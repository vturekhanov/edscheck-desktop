package kz.edscheck.provider.kalkan;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.ASN1TaggedObject;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import kz.gov.pki.kalkan.ocsp.SingleResp;

public final class EmbeddedRevocation {
    private static final String PROV = "KALKAN";

    private static final String OID_RI_OCSP_RESPONSE = "1.3.6.1.5.5.7.16.2";
    private static final int TAG_REVOCATION_INFO_OTHER = 1;

    private EmbeddedRevocation() {
    }

    public record CrlsEntry(X509CRL crl, BasicOCSPResp ocsp) {
    }

    public static CrlsEntry parseCrlsBlob(byte[] blob) {
        try {
            DEREncodable obj = new ASN1InputStream(blob).readObject();
            if (obj instanceof ASN1TaggedObject t && t.getTagNo() == TAG_REVOCATION_INFO_OTHER) {
                ASN1Sequence other = ASN1Sequence.getInstance(t, false);
                DERObjectIdentifier oid = DERObjectIdentifier.getInstance(other.getObjectAt(0));
                if (!OID_RI_OCSP_RESPONSE.equals(oid.getId())) {
                    return new CrlsEntry(null, null); 
                }
                byte[] payload =
                    ((kz.gov.pki.kalkan.asn1.ASN1Encodable) other.getObjectAt(1)).getDEREncoded();
                OCSPResp resp = new OCSPResp(payload);
                if (resp.getStatus() != 0) {
                    return new CrlsEntry(null, null); 
                }
                if (resp.getResponseObject() instanceof BasicOCSPResp basic) {
                    return new CrlsEntry(null, basic);
                }
                return new CrlsEntry(null, null);
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509", PROV);
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(blob));
            return new CrlsEntry(crl, null);
        } catch (Exception ignored) {
            return new CrlsEntry(null, null);
        }
    }

    public static List<CrlsEntry> parseCrlsBlobs(List<byte[]> crlBlobs) {
        List<CrlsEntry> out = new ArrayList<>();
        for (byte[] blob : crlBlobs) {
            CrlsEntry e = parseCrlsBlob(blob);
            if (e.crl() != null || e.ocsp() != null) {
                out.add(e);
            }
        }
        return out;
    }

    public static boolean matchesCrl(X509CRL crl, X509Certificate signerCert) {
        return crl.getIssuerX500Principal().equals(signerCert.getIssuerX500Principal());
    }

    public static X509CRL findMatchingCrl(List<CrlsEntry> entries, X509Certificate signerCert) {
        for (CrlsEntry e : entries) {
            if (e.crl() != null && matchesCrl(e.crl(), signerCert)) {
                return e.crl();
            }
        }
        return null;
    }

    public static boolean matchesOcsp(BasicOCSPResp ocsp, X509Certificate issuerCert, X509Certificate target) {
        for (SingleResp sr : ocsp.getResponses()) {
            try {
                CertificateID expected = new CertificateID(
                    sr.getCertID().getHashAlgOID(), issuerCert, target.getSerialNumber(), PROV);
                if (expected.equals(sr.getCertID())) {
                    return true;
                }
            } catch (Exception ignored) {

            }
        }
        return false;
    }

    public static BasicOCSPResp findMatchingOcsp(
            List<CrlsEntry> entries, X509Certificate issuerCert, X509Certificate target) {
        for (CrlsEntry e : entries) {
            if (e.ocsp() != null && matchesOcsp(e.ocsp(), issuerCert, target)) {
                return e.ocsp();
            }
        }
        return null;
    }
}
