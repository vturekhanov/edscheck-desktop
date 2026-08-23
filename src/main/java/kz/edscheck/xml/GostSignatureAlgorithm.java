package kz.edscheck.xml;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignatureException;

public abstract class GostSignatureAlgorithm extends SignatureAlgorithmSpi {
    private final Signature signature;

    public GostSignatureAlgorithm() throws XMLSignatureException {
        String jceName = JCEMapper.translateURItoJCEID(engineGetURI());
        try {
            this.signature = Signature.getInstance(jceName, JCEMapper.getProviderId());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected String engineGetJCEAlgorithmString() {
        return signature.getAlgorithm();
    }

    @Override
    protected String engineGetJCEProviderName() {
        return signature.getProvider().getName();
    }

    @Override
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            signature.update(input);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            signature.update(input);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            signature.update(buf, offset, len);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineInitSign(Key signingKey) throws XMLSignatureException {
        try {
            signature.initSign((PrivateKey) signingKey);
        } catch (InvalidKeyException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineInitSign(Key signingKey, SecureRandom secureRandom) throws XMLSignatureException {
        try {
            signature.initSign((PrivateKey) signingKey, secureRandom);
        } catch (InvalidKeyException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec)
            throws XMLSignatureException {

        engineInitSign(signingKey);
    }

    @Override
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            return signature.sign();
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineInitVerify(Key verificationKey) throws XMLSignatureException {

        engineInitVerify(verificationKey, signature);
    }

    @Override
    protected boolean engineVerify(byte[] signatureBytes) throws XMLSignatureException {
        try {
            return signature.verify(signatureBytes);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec) throws XMLSignatureException {
        try {
            signature.setParameter(algorithmParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    protected void engineSetHMACOutputLength(int hmacOutputLength) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    static final String URI_2015 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
    static final String JCE_NAME_2015 = "ECGOST3410-2015-512";

    static final String URI_2004 = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
    static final String JCE_NAME_2004 = "GOST34311withECGOST34310";

    public static final class GostR34102015GostR34112015512 extends GostSignatureAlgorithm {
        public GostR34102015GostR34112015512() throws XMLSignatureException {
            super();
        }

        @Override
        public String engineGetURI() {
            return URI_2015;
        }
    }

    public static final class Gost34310Gost34311 extends GostSignatureAlgorithm {
        public Gost34310Gost34311() throws XMLSignatureException {
            super();
        }

        @Override
        public String engineGetURI() {
            return URI_2004;
        }
    }
}
