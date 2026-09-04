package kz.edscheck.trust;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigestSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

public final class BcBackend implements CryptoBackend {
    private static final String OID_DIGEST_95 = "1.2.398.3.10.1.3.1";
    private static final String OID_DIGEST_2015_256 = "1.2.398.3.10.1.3.2";
    private static final String OID_DIGEST_2015_512 = "1.2.398.3.10.1.3.3";
    private static final String OID_SIG_2004 = "1.2.398.3.10.1.1.1.2";
    private static final String OID_SIG_2015_256 = "1.2.398.3.10.1.1.2.3.1";
    private static final String OID_SIG_2015_512 = "1.2.398.3.10.1.1.2.3.2";

    private static final Map<String, String> CURVE_OID_TO_BC_NAME = Map.of(
        "1.2.398.3.10.1.1.1.1.1", "GostR3410-2001-CryptoPro-A",
        "1.2.398.3.10.1.1.2.1.1", "Tc26-Gost-3410-12-256-paramSetA",
        "1.2.398.3.10.1.1.2.2.1", "Tc26-Gost-3410-12-512-paramSetA");

    private static final Set<String> KEY_ALG_OIDS = Set.of(
        "1.2.398.3.10.1.1.1.1", "1.2.398.3.10.1.1.2.1", "1.2.398.3.10.1.1.2.2");

    @Override
    public String engineName() {
        return "bc";
    }

    @Override
    public String jceProviderName() {
        return "BC";
    }

    @Override
    public boolean available() {

        return true;
    }

    @Override
    public void ensureRegistered() {

        if (Security.getProvider("BC") == null) {
            BouncyCastleProvider bc = new BouncyCastleProvider();
            registerKazakhAliases(bc);
            registerKazakhKeyConverters(bc);
            Security.addProvider(bc);
        }
    }

    private static void registerKazakhKeyConverters(BouncyCastleProvider bc) {
        AsymmetricKeyInfoConverter converter = new KzKeyInfoConverter();
        for (String keyAlgOid : KEY_ALG_OIDS) {
            bc.addKeyInfoConverter(new ASN1ObjectIdentifier(keyAlgOid), converter);
        }
    }

    private static void registerKazakhAliases(Provider bc) {

        bc.put("MessageDigest.GOST3411", GostD95Digest.class.getName());
        bc.put("Alg.Alias.MessageDigest.GOST3411-2015-256", "GOST3411-2012-256");
        bc.put("Alg.Alias.MessageDigest.GOST3411-2015-512", "GOST3411-2012-512");
        bc.put("Signature." + OID_SIG_2004, SigGost2004.class.getName());
        bc.put("Signature." + OID_SIG_2015_256, SigGost2015_256.class.getName());
        bc.put("Signature." + OID_SIG_2015_512, SigGost2015_512.class.getName());

        bc.put("Alg.Alias.MessageDigest.GOST34311", "GOST3411");
        bc.put("Alg.Alias.Signature.ECGOST3410-2015-512", OID_SIG_2015_512);
        bc.put("Alg.Alias.Signature.GOST34311withECGOST34310", OID_SIG_2004);
    }

    private static Digest gostDigest(String digestOid) {
        if (OID_DIGEST_95.equals(digestOid)) {
            return new GOST3411Digest(GOST28147Engine.getSBox("D-TEST"));
        }
        if (OID_DIGEST_2015_256.equals(digestOid)) {
            return new GOST3411_2012_256Digest();
        }
        if (OID_DIGEST_2015_512.equals(digestOid)) {
            return new GOST3411_2012_512Digest();
        }
        throw new IllegalArgumentException(Messages.get(MsgKey.PROVIDER_BC_UNKNOWN_DIGEST_OID, digestOid));
    }

    private static byte[] reversed(byte[] value) {
        byte[] out = new byte[value.length];
        for (int i = 0; i < value.length; i++) {
            out[i] = value[value.length - 1 - i];
        }
        return out;
    }

    private static ECPublicKeyParameters gostPublicKey(SubjectPublicKeyInfo spki) throws InvalidKeyException {
        ASN1Sequence params;
        try {
            params = ASN1Sequence.getInstance(spki.getAlgorithm().getParameters());
        } catch (Exception e) {
            throw new InvalidKeyException(
                Messages.get(MsgKey.PROVIDER_BC_KEY_PARAMS_PARSE_FAILED, e.getMessage()), e);
        }
        String curveOid = ASN1ObjectIdentifier.getInstance(params.getObjectAt(0)).getId();
        String curveName = CURVE_OID_TO_BC_NAME.get(curveOid);
        if (curveName == null) {
            throw new InvalidKeyException(Messages.get(MsgKey.PROVIDER_BC_UNKNOWN_CURVE, curveOid));
        }
        X9ECParameters x9 = ECGOST3410NamedCurves.getByNameX9(curveName);
        ECDomainParameters domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
        byte[] raw;
        try {
            raw = ASN1OctetString.getInstance(
                ASN1Primitive.fromByteArray(spki.getPublicKeyData().getOctets())).getOctets();
        } catch (Exception e) {
            throw new InvalidKeyException(
                Messages.get(MsgKey.PROVIDER_BC_KEY_BYTES_PARSE_FAILED, e.getMessage()), e);
        }
        int half = raw.length / 2;
        ECPoint point = domain.getCurve().createPoint(
            new BigInteger(1, reversed(Arrays.copyOfRange(raw, 0, half))),
            new BigInteger(1, reversed(Arrays.copyOfRange(raw, half, raw.length))));
        if (!point.isValid()) {
            throw new InvalidKeyException(Messages.get(MsgKey.PROVIDER_BC_POINT_NOT_ON_CURVE, curveName));
        }
        return new ECPublicKeyParameters(point, domain);
    }

    private static PublicKey gostTypedPublicKey(SubjectPublicKeyInfo spki) throws InvalidKeyException {
        gostPublicKey(spki);
        return new KzPublicKey(spki);
    }

    private static boolean verifyGost(
            SubjectPublicKeyInfo spki, byte[] signedBytes, byte[] signatureBytes, String digestOid)
            throws InvalidKeyException {
        ECPublicKeyParameters pub = gostPublicKey(spki);
        Digest d = gostDigest(digestOid);
        d.update(signedBytes, 0, signedBytes.length);
        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);
        int half = signatureBytes.length / 2;
        BigInteger r = new BigInteger(1, reversed(Arrays.copyOfRange(signatureBytes, 0, half)));
        BigInteger s = new BigInteger(1, reversed(Arrays.copyOfRange(signatureBytes, half, signatureBytes.length)));

        ECGOST3410Signer signer = new ECGOST3410Signer();
        signer.init(false, pub);
        return signer.verifySignature(hash, r, s);
    }

    public static final class GostD95Digest extends MessageDigestSpi {
        private final Digest d = gostDigest(OID_DIGEST_95);

        @Override
        protected void engineUpdate(byte input) {
            d.update(input);
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            d.update(input, offset, len);
        }

        @Override
        protected byte[] engineDigest() {
            byte[] out = new byte[d.getDigestSize()];
            d.doFinal(out, 0);
            return out;
        }

        @Override
        protected void engineReset() {
            d.reset();
        }

        @Override
        protected int engineGetDigestLength() {
            return d.getDigestSize();
        }
    }

    private static final class KzPublicKey implements PublicKey {
        private final byte[] encoded;

        KzPublicKey(SubjectPublicKeyInfo spki) throws InvalidKeyException {
            try {
                this.encoded = spki.getEncoded();
            } catch (IOException e) {
                throw new InvalidKeyException(
                    Messages.get(MsgKey.PROVIDER_BC_SPKI_PARSE_FAILED, e.getMessage()), e);
            }
        }

        @Override
        public String getAlgorithm() {
            return "ECGOST3410";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return encoded.clone();
        }
    }

    private static final class KzKeyInfoConverter implements AsymmetricKeyInfoConverter {
        @Override
        public PublicKey generatePublic(SubjectPublicKeyInfo spki) throws IOException {
            try {
                return gostTypedPublicKey(spki);
            } catch (InvalidKeyException e) {
                throw new IOException(e.getMessage(), e);
            }
        }

        @Override
        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
            throw new IOException(Messages.get(MsgKey.PROVIDER_BC_PRIVATE_KEY_NOT_SUPPORTED));
        }
    }

    private abstract static class KzSignature extends SignatureSpi {
        private final String digestOid;
        private final java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        private SubjectPublicKeyInfo spki;

        KzSignature(String digestOid) {
            this.digestOid = digestOid;
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            try {
                spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            } catch (Exception e) {
                throw new InvalidKeyException(
                    Messages.get(MsgKey.PROVIDER_BC_SPKI_PARSE_FAILED, e.getMessage()), e);
            }
            buf.reset();
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) {
            throw new UnsupportedOperationException(Messages.get(MsgKey.PROVIDER_BC_VERIFY_ONLY));
        }

        @Override
        protected void engineUpdate(byte b) {
            buf.write(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) {
            buf.write(b, off, len);
        }

        @Override
        protected byte[] engineSign() {
            throw new UnsupportedOperationException(Messages.get(MsgKey.PROVIDER_BC_VERIFY_ONLY));
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            try {
                return verifyGost(spki, buf.toByteArray(), sigBytes, digestOid);
            } catch (InvalidKeyException e) {
                throw new SignatureException(e.getMessage(), e);
            }
        }

        @Override
        @SuppressWarnings("deprecation")
        protected void engineSetParameter(String param, Object value) {
            throw new UnsupportedOperationException(param);
        }

        @Override
        @SuppressWarnings("deprecation")
        protected Object engineGetParameter(String param) {
            throw new UnsupportedOperationException(param);
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params) {

        }
    }

    public static final class SigGost2004 extends KzSignature {
        public SigGost2004() {
            super(OID_DIGEST_95);
        }
    }

    public static final class SigGost2015_256 extends KzSignature {
        public SigGost2015_256() {
            super(OID_DIGEST_2015_256);
        }
    }

    public static final class SigGost2015_512 extends KzSignature {
        public SigGost2015_512() {
            super(OID_DIGEST_2015_512);
        }
    }
}
