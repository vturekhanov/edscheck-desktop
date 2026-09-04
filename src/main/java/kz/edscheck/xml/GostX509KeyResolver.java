package kz.edscheck.xml;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

import kz.edscheck.trust.ActiveBackend;

final class GostX509KeyResolver extends KeyResolverSpi {
    @Override
    protected boolean engineCanResolve(Element element, String baseUri, StorageResolver storage) {
        return XmlNamespaces.XMLDSIG.equals(element.getNamespaceURI());
    }

    @Override
    protected PublicKey engineResolvePublicKey(
            Element element, String baseUri, StorageResolver storage, boolean secureValidation)
            throws KeyResolverException {
        X509Certificate cert = engineResolveX509Certificate(element, baseUri, storage, secureValidation);
        return cert == null ? null : cert.getPublicKey();
    }

    @Override
    protected X509Certificate engineResolveX509Certificate(
            Element element, String baseUri, StorageResolver storage, boolean secureValidation)
            throws KeyResolverException {
        try {
            Element[] certNodes = XMLUtils.selectDsNodes(element.getFirstChild(), "X509Certificate");
            if (certNodes == null || certNodes.length == 0) {

                Element x509Data = XMLUtils.selectDsNode(element.getFirstChild(), "X509Data", 0);
                return x509Data == null ? null
                    : engineResolveX509Certificate(x509Data, baseUri, storage, secureValidation);
            }
            for (Element certNode : certNodes) {
                X509Certificate cert = parseCertificate(certNode);
                if (cert != null) {
                    return cert;
                }
            }
            return null;
        } catch (Exception e) {
            throw new KeyResolverException(e);
        }
    }

    @Override
    protected SecretKey engineResolveSecretKey(
            Element element, String baseUri, StorageResolver storage, boolean secureValidation) {
        return null;
    }

    @Override
    protected PrivateKey engineResolvePrivateKey(
            Element element, String baseUri, StorageResolver storage, boolean secureValidation) {
        return null;
    }

    private static X509Certificate parseCertificate(Element certElement) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(certElement.getTextContent().trim());
        try (ByteArrayInputStream in = new ByteArrayInputStream(der)) {
            CertificateFactory cf = ActiveBackend.x509CertificateFactory();
            return (X509Certificate) cf.generateCertificate(in);
        }
    }
}
