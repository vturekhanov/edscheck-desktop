package kz.edscheck.trust;

import java.security.cert.X509Certificate;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.x509.X509Name;

public final class Authorities {
    private static final Map<String, String> DISPLAY = Map.of(
        "nca", Messages.get(MsgKey.CA_NCA),
        "btsd", Messages.get(MsgKey.CA_BTSD),
        "ucgo", Messages.get(MsgKey.CA_UCGO));

    private Authorities() {
    }

    private static String attr(X500Principal name, kz.gov.pki.kalkan.asn1.DERObjectIdentifier oid) {
        try {
            ASN1Sequence seq = (ASN1Sequence)
                new ASN1InputStream(name.getEncoded()).readObject();
            X509Name x509Name = X509Name.getInstance(seq);
            @SuppressWarnings("unchecked")
            var values = x509Name.getValues(oid);
            return values.isEmpty() ? "" : String.valueOf(values.get(0));
        } catch (Exception e) { 
            return "";
        }
    }

    private static boolean isNca(X500Principal name) {
        return attr(name, X509Name.CN).contains("ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ");
    }

    private static boolean isBtsd(X500Principal name) {
        return "BTS Digital".equals(attr(name, X509Name.O)) || attr(name, X509Name.CN).contains("BTSD");
    }

    private static boolean isUcgo(X500Principal name) {
        return attr(name, X509Name.CN).contains("Удостоверяющий центр Государственных органов");
    }

    public static String detectPrincipal(X500Principal name) {
        if (name == null) {
            return null;
        }
        if (isNca(name)) {
            return "nca";
        }
        if (isBtsd(name)) {
            return "btsd";
        }
        if (isUcgo(name)) {
            return "ucgo";
        }
        return null;
    }

    public static String detect(X509Certificate anchorCert) {
        if (anchorCert == null) {
            return null;
        }
        return detectPrincipal(anchorCert.getSubjectX500Principal());
    }

    public static String display(String code) {
        if (code == null) {
            return Messages.get(MsgKey.CA_UNKNOWN);
        }
        return DISPLAY.getOrDefault(code, code);
    }
}
