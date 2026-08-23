package kz.edscheck.xml;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.x509.X509CertificateStructure;
import kz.gov.pki.kalkan.jce.provider.X509CertificateObject;

final class XmlCertificates {
    private static final Base64.Decoder BASE64 = Base64.getMimeDecoder();

    private XmlCertificates() {
    }

    static X509Certificate parse(String base64) {
        try {
            byte[] der = BASE64.decode(base64.trim());
            ASN1InputStream ain = new ASN1InputStream(der);
            X509CertificateStructure struct = X509CertificateStructure.getInstance(ain.readObject());
            return new X509CertificateObject(struct);
        } catch (RuntimeException | CertificateParsingException | IOException e) {
            throw new ContainerException(Messages.get(MsgKey.XML_CERTIFICATE_NOT_PARSED, e.getMessage()), e);
        }
    }
}
