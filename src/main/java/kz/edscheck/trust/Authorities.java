package kz.edscheck.trust;

import java.security.cert.X509Certificate;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

public final class Authorities {
    private static final Map<String, String> DISPLAY = Map.of(
        "nca", Messages.get(MsgKey.CA_NCA),
        "btsd", Messages.get(MsgKey.CA_BTSD),
        "ucgo", Messages.get(MsgKey.CA_UCGO));

    private Authorities() {
    }

    private static String attr(X500Principal name, ASN1ObjectIdentifier oid) {
        try {
            X500Name x500Name = X500Name.getInstance(name.getEncoded());
            for (RDN rdn : x500Name.getRDNs(oid)) {
                for (AttributeTypeAndValue atv : rdn.getTypesAndValues()) {
                    if (atv.getType().equals(oid)) {
                        return rawValue(atv.getValue());
                    }
                }
            }
            return "";
        } catch (Exception e) { 
            return "";
        }
    }

    private static String rawValue(ASN1Encodable value) {
        if (value instanceof ASN1String) {
            return ((ASN1String) value).getString();
        }
        return value.toString();
    }

    private static boolean isNca(X500Principal name) {
        return attr(name, BCStyle.CN).contains("ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ");
    }

    private static boolean isBtsd(X500Principal name) {
        return "BTS Digital".equals(attr(name, BCStyle.O)) || attr(name, BCStyle.CN).contains("BTSD");
    }

    private static boolean isUcgo(X500Principal name) {
        return attr(name, BCStyle.CN).contains("Удостоверяющий центр Государственных органов");
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
