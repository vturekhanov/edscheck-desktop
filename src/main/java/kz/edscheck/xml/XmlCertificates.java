package kz.edscheck.xml;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

final class XmlCertificates {
    private static final Base64.Decoder BASE64 = Base64.getMimeDecoder();

    private XmlCertificates() {
    }

    static X509Certificate parse(String base64) {
        try {
            byte[] der = BASE64.decode(base64.trim());
            ASN1InputStream ain = new ASN1InputStream(der);
            Certificate struct = Certificate.getInstance(ain.readObject());
            return new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(struct));
        } catch (RuntimeException | CertificateException | IOException e) {
            throw new ContainerException(Messages.get(MsgKey.XML_CERTIFICATE_NOT_PARSED, e.getMessage()), e);
        }
    }
}
