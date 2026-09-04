package kz.edscheck.provider.jce;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.trust.DigestAlgorithms;

final class CmsBridge {
    private CmsBridge() {
    }

    private static final Set<String> COMBINED_SIGNATURE_OIDS = Set.of(
        "1.2.398.3.10.1.1.1.2",    
        "1.2.398.3.10.1.1.2.3.1",  
        "1.2.398.3.10.1.1.2.3.2"); 

    private static final DefaultCMSSignatureAlgorithmNameGenerator DEFAULT_NAME_GENERATOR =
        new DefaultCMSSignatureAlgorithmNameGenerator();
    private static final DefaultSignatureAlgorithmIdentifierFinder DEFAULT_SIG_FINDER =
        new DefaultSignatureAlgorithmIdentifierFinder();

    private static final CMSSignatureAlgorithmNameGenerator SIG_NAME_GENERATOR =
        (digestAlg, sigAlg) -> COMBINED_SIGNATURE_OIDS.contains(sigAlg.getAlgorithm().getId())
            ? sigAlg.getAlgorithm().getId()
            : DEFAULT_NAME_GENERATOR.getSignatureName(digestAlg, sigAlg);

    private static final SignatureAlgorithmIdentifierFinder SIG_ALG_FINDER =
        name -> COMBINED_SIGNATURE_OIDS.contains(name)
            ? new AlgorithmIdentifier(new ASN1ObjectIdentifier(name))
            : DEFAULT_SIG_FINDER.find(name);

    private static final class RawAttrs extends SignerInformation {
        RawAttrs(SignerInformation base) {
            super(base);
        }

        @Override
        public byte[] getEncodedSignedAttributes() throws IOException {
            ASN1Set attrs = toASN1Structure().getAuthenticatedAttributes();
            return attrs == null ? null : attrs.getEncoded(ASN1Encoding.DL);
        }
    }

    static boolean verify(SignerInformation si, X509Certificate cert, String provider) throws Exception {
        return new RawAttrs(si).verify(verifierFor(cert, provider));
    }

    static SignerInformationVerifier verifierFor(X509Certificate cert, String provider) {
        X509CertificateHolder holder = holderOf(cert);
        return new SignerInformationVerifier(
            SIG_NAME_GENERATOR, SIG_ALG_FINDER,
            new JceContentVerifierProvider(holder, cert, provider),
            alg -> digestCalculator(alg, provider));
    }

    static DigestCalculator digestCalculator(AlgorithmIdentifier alg, String provider)
            throws OperatorCreationException {
        String oid = alg.getAlgorithm().getId();
        String jceName = DigestAlgorithms.jceName(oid);
        if (jceName == null) {
            throw new OperatorCreationException(Messages.get(MsgKey.PROVIDER_CMS_BRIDGE_UNKNOWN_DIGEST_ALG, oid));
        }
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(jceName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new OperatorCreationException(e.getMessage(), e);
        }
        return new JceDigestCalculator(alg, md);
    }

    static CertificateID certificateId(
            ASN1ObjectIdentifier hashAlgOid, X509Certificate issuer, BigInteger serial, String provider)
            throws Exception {
        AlgorithmIdentifier alg = new AlgorithmIdentifier(hashAlgOid, DERNull.INSTANCE);
        DigestCalculator calc = digestCalculator(alg, provider);
        return new CertificateID(calc, holderOf(issuer), serial);
    }

    static ContentVerifierProvider contentVerifierProvider(X509Certificate cert, String provider) {
        return new JceContentVerifierProvider(holderOf(cert), cert, provider);
    }

    static X509Certificate[] certsOf(BasicOCSPResp basic, String provider) {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(provider);
        List<X509Certificate> out = new ArrayList<>();
        for (X509CertificateHolder h : basic.getCerts()) {
            try {
                out.add(converter.getCertificate(h));
            } catch (Exception ignored) {

            }
        }
        return out.toArray(new X509Certificate[0]);
    }

    private static X509CertificateHolder holderOf(X509Certificate cert) {
        try {
            return new JcaX509CertificateHolder(cert);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(
                Messages.get(MsgKey.PROVIDER_CMS_BRIDGE_CERT_NOT_ENCODABLE, e.getMessage()), e);
        }
    }

    private static final class JceDigestCalculator implements DigestCalculator {
        private final AlgorithmIdentifier alg;
        private final MessageDigest md;
        private final OutputStream out;

        JceDigestCalculator(AlgorithmIdentifier alg, MessageDigest md) {
            this.alg = alg;
            this.md = md;
            this.out = new OutputStream() {
                @Override public void write(int b) {
                    md.update((byte) b);
                }

                @Override public void write(byte[] b, int off, int len) {
                    md.update(b, off, len);
                }
            };
        }

        @Override public AlgorithmIdentifier getAlgorithmIdentifier() {
            return alg;
        }

        @Override public OutputStream getOutputStream() {
            return out;
        }

        @Override public byte[] getDigest() {
            return md.digest();
        }
    }

    private static final class JceContentVerifierProvider implements ContentVerifierProvider {
        private final X509CertificateHolder holder;
        private final X509Certificate cert;
        private final String provider;

        JceContentVerifierProvider(X509CertificateHolder holder, X509Certificate cert, String provider) {
            this.holder = holder;
            this.cert = cert;
            this.provider = provider;
        }

        @Override public boolean hasAssociatedCertificate() {
            return true;
        }

        @Override public X509CertificateHolder getAssociatedCertificate() {
            return holder;
        }

        @Override public ContentVerifier get(AlgorithmIdentifier sigAlg) throws OperatorCreationException {
            String oid = sigAlg.getAlgorithm().getId();
            Signature signature;
            try {
                signature = Signature.getInstance(oid, provider);
                signature.initVerify(cert.getPublicKey());
            } catch (Exception e) {
                throw new OperatorCreationException(e.getMessage(), e);
            }
            return new JceContentVerifier(sigAlg, signature);
        }
    }

    private static final class JceContentVerifier implements ContentVerifier {
        private final AlgorithmIdentifier alg;
        private final Signature signature;
        private final OutputStream out;

        JceContentVerifier(AlgorithmIdentifier alg, Signature signature) {
            this.alg = alg;
            this.signature = signature;
            this.out = new OutputStream() {
                @Override public void write(int b) throws IOException {
                    try {
                        signature.update((byte) b);
                    } catch (SignatureException e) {
                        throw new IOException(e);
                    }
                }

                @Override public void write(byte[] b, int off, int len) throws IOException {
                    try {
                        signature.update(b, off, len);
                    } catch (SignatureException e) {
                        throw new IOException(e);
                    }
                }
            };
        }

        @Override public AlgorithmIdentifier getAlgorithmIdentifier() {
            return alg;
        }

        @Override public OutputStream getOutputStream() {
            return out;
        }

        @Override public boolean verify(byte[] expected) {
            try {
                return signature.verify(expected);
            } catch (SignatureException e) {
                return false; 
            }
        }
    }
}
