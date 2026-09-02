package kz.edscheck.parsing;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.DERGeneralizedTime;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DERUTCTime;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
import kz.gov.pki.kalkan.asn1.x509.PolicyInformation;
import kz.gov.pki.kalkan.asn1.x509.X509Name;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.Encoding;
import kz.edscheck.domain.KeyAlgorithm;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.ArchiveTimestampInfo;
import kz.edscheck.provider.KeyUsageInfo;
import kz.edscheck.rules.KzEkuRoles;
import kz.edscheck.trust.DigestAlgorithms;
import kz.edscheck.trust.Digests;

public final class Parsing {
    private static final String PROV = "KALKAN";

    private static final DERObjectIdentifier OID_SIGNATURE_TS_TOKEN =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.14");
    private static final DERObjectIdentifier OID_REVOCATION_VALUES =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.24");
    private static final DERObjectIdentifier OID_ARCHIVE_TS_V1 =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.27");
    private static final DERObjectIdentifier OID_ARCHIVE_TS_V2 =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.48");
    private static final DERObjectIdentifier OID_ARCHIVE_TS_V3 =
        new DERObjectIdentifier("0.4.0.1733.2.4");

    private static final DERObjectIdentifier OID_SIGNING_CERTIFICATE_V2 =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.47");

    private record MandatoryBbAttr(DERObjectIdentifier oid, String name) {
    }

    private static final List<MandatoryBbAttr> MANDATORY_BB_ATTRS = List.of(
        new MandatoryBbAttr(CMSAttributes.contentType, "content-type"),
        new MandatoryBbAttr(CMSAttributes.messageDigest, "message-digest"),
        new MandatoryBbAttr(CMSAttributes.signingTime, "signing-time"),
        new MandatoryBbAttr(OID_SIGNING_CERTIFICATE_V2, "signing-certificate-v2"));

    private static final String OID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
    private static final DERObjectIdentifier OID_ORGANIZATION_IDENTIFIER =
        new DERObjectIdentifier("2.5.4.97");
    private static final String OID_RSA = "1.2.840.113549.1.1.1";
    private static final String OID_KZ_PREFIX = "1.2.398";

    static {
        if (Security.getProvider(PROV) == null) {
            Security.addProvider(new KalkanProvider());
        }
    }

    private Parsing() {
    }

    public record DecodedContainer(Encoding encoding, byte[] der) {
    }

    public static DecodedContainer decodeContainer(byte[] raw) {
        int i = 0;
        while (i < raw.length && isAsciiWhitespace(raw[i])) {
            i++;
        }
        if (i + 5 <= raw.length && matches(raw, i, "-----")) {
            byte[] der = pemUnarmor(raw, i);
            return new DecodedContainer(Encoding.BASE64, der);
        }
        if (i < raw.length && raw[i] == 0x30) {
            return new DecodedContainer(Encoding.DER, raw);
        }
        try {
            String stripped = stripAllWhitespace(raw, i);
            byte[] der = Base64.getDecoder().decode(stripped);
            if (der.length > 0 && der[0] == 0x30) {
                return new DecodedContainer(Encoding.BASE64, der);
            }
        } catch (IllegalArgumentException ignored) {

        }
        return new DecodedContainer(Encoding.DER, raw);
    }

    public static ParsedContainer parseContainer(byte[] raw, List<X509Certificate> extraCerts) {
        Decoded d = decodeForParsing(raw, extraCerts);
        return assembleParsedContainer(
            d.encoding(), d.der(), d.signerInfos(), d.certStore(), d.containerCerts(), d.bySubject());
    }

    public static ParsedContainer parseContainer(
            byte[] raw, List<X509Certificate> extraCerts, DocumentSource document) {
        Decoded d = decodeForParsing(raw, extraCerts);
        Collection<SignerInformation> signerInfos = d.signerInfos();
        if (document != null && d.sd().getSignedContent() == null) {
            Map<String, MessageDigest> mdByOid = neededDigestAlgorithms(signerInfos);
            if (!mdByOid.isEmpty()) {
                try (InputStream in = document.open()) {
                    Digests.updateAll(in, mdByOid.values());
                } catch (IOException e) {
                    throw new ContainerException(
                        Messages.get(MsgKey.CONTAINER_DOCUMENT_READ_FAILED, e.getMessage()), e);
                }
                Map<String, byte[]> digestsByOid = new LinkedHashMap<>();
                for (Map.Entry<String, MessageDigest> e : mdByOid.entrySet()) {
                    digestsByOid.put(e.getKey(), e.getValue().digest());
                }
                signerInfos = bindDigests(signerInfos, d.der(), digestsByOid);
            }
        }
        return assembleParsedContainer(
            d.encoding(), d.der(), signerInfos, d.certStore(), d.containerCerts(), d.bySubject());
    }

    public static ParsedContainer parseContainer(
            byte[] raw, List<X509Certificate> extraCerts, Map<String, byte[]> precomputedDigests) {
        Decoded d = decodeForParsing(raw, extraCerts);
        Collection<SignerInformation> signerInfos = d.signerInfos();
        if (precomputedDigests != null && !precomputedDigests.isEmpty()
                && d.sd().getSignedContent() == null) {
            signerInfos = bindDigests(signerInfos, d.der(), precomputedDigests);
        }
        return assembleParsedContainer(
            d.encoding(), d.der(), signerInfos, d.certStore(), d.containerCerts(), d.bySubject());
    }

    public static ParsedContainer parseAttached(DocumentSource container, List<X509Certificate> extraCerts) {
        AttachedSplitter.Split split;
        try {
            split = AttachedSplitter.trySplit(container);
        } catch (AttachedSplitter.SplitFailedException | IOException e) {
            return parseContainer(readAllBytesForFallback(container), extraCerts);
        }
        return parseContainer(split.skeleton(), extraCerts, split.digestsByOid());
    }

    private static byte[] readAllBytesForFallback(DocumentSource container) {
        try {
            return container.readAllBytes();
        } catch (IOException e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
        }
    }

    private record Decoded(
            Encoding encoding, byte[] der, CMSSignedData sd, CertStore certStore,
            List<X509Certificate> containerCerts, Map<X500Principal, X509Certificate> bySubject,
            Collection<SignerInformation> signerInfos) {
    }

    private static Decoded decodeForParsing(byte[] raw, List<X509Certificate> extraCerts) {
        DecodedContainer decoded = decodeContainer(raw);
        CMSSignedData sd;
        try {
            sd = new CMSSignedData(decoded.der());
        } catch (Exception e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()), e);
        }

        CertStore certStore;
        List<X509Certificate> containerCerts;
        try {
            certStore = sd.getCertificatesAndCRLs("Collection", PROV);
            containerCerts = new ArrayList<>();
            for (java.security.cert.Certificate c : certStore.getCertificates(null)) {
                containerCerts.add((X509Certificate) c);
            }
        } catch (Exception e) {
            throw new ContainerException(Messages.get(MsgKey.PARSING_CERTS_READ_FAILED, e.getMessage()), e);
        }

        Map<X500Principal, X509Certificate> bySubject = new HashMap<>();
        for (X509Certificate c : containerCerts) {
            bySubject.putIfAbsent(c.getSubjectX500Principal(), c);
        }
        if (extraCerts != null) {
            for (X509Certificate c : extraCerts) {
                bySubject.putIfAbsent(c.getSubjectX500Principal(), c);
            }
        }

        @SuppressWarnings("unchecked")
        Collection<SignerInformation> signerInfos =
            (Collection<SignerInformation>) sd.getSignerInfos().getSigners();
        if (signerInfos.isEmpty()) {
            throw new ContainerException(Messages.get(MsgKey.PARSING_NO_SIGNERS));
        }

        return new Decoded(decoded.encoding(), decoded.der(), sd, certStore, containerCerts, bySubject, signerInfos);
    }

    private static ParsedContainer assembleParsedContainer(
            Encoding encoding, byte[] der, Collection<SignerInformation> signerInfos,
            CertStore certStore, List<X509Certificate> containerCerts,
            Map<X500Principal, X509Certificate> bySubject) {
        SignedDataContext sdContext = signedDataContext(der);

        boolean hasRevFromCrls = !sdContext.crlBlobs().isEmpty();

        List<ParsedSigner> signers = new ArrayList<>();
        List<String> bcOrderKeys = new ArrayList<>();
        boolean anyTs = false;
        boolean anyRev = false;
        boolean anyArchive = false;
        int index = 0;
        for (SignerInformation si : signerInfos) {
            X509Certificate cert = resolveSignerCert(certStore, si);
            Certificate certificate = cert != null ? certificateFields(cert) : Certificate.empty();
            KeyUsageInfo keyUsage = cert != null ? keyUsageInfo(cert) : new KeyUsageInfo();
            List<Certificate> chain = resolveChain(cert, bySubject);
            Instant signingTime = signedAttrTime(si);
            TstInfo tst = timestampFromUnsigned(si);
            boolean hasRev = hasUnsignedAttr(si, OID_REVOCATION_VALUES) || hasRevFromCrls;
            EssBinding ess = signingCertificateBinding(si);
            ArchiveData archive = archiveData(si, containerCerts, sdContext);
            anyTs = anyTs || tst.present();
            anyRev = anyRev || hasRev;
            anyArchive = anyArchive || archive.info().count() > 0 || archive.info().legacyCount() > 0;

            signers.add(new ParsedSigner(
                index, certificate, keyUsage, signingTime, tst.genTime(), tst.present(),
                hasRev, tst.tsaEkuOk(), chain, archive.info(),
                cert, ess.alg(), ess.hash(), tst.tsaCert(), tst.tsaCerts(), tst.tokenDer(),
                si.getSignature(), tst.imprintAlg(), tst.imprintHash(), archive.marks(), si,
                missingMandatoryBbAttrs(si.getSignedAttributes()), tst.crlBlobs()));
            bcOrderKeys.add(signerInfoSignatureKey(si));
            index++;
        }

        signers = reorderToFileOrder(signers, bcOrderKeys, fileOrderSignatureKeys(der));
        List<ParsedSigner> reindexed = new ArrayList<>(signers.size());
        for (int i = 0; i < signers.size(); i++) {
            reindexed.add(withIndex(signers.get(i), i));
        }

        return new ParsedContainer(
            encoding,
            cadesLevel(anyTs, anyRev, anyArchive, missingMandatoryBbAttrs(signerInfos)),
            reindexed, containerCerts, sdContext.crlBlobs());
    }

    static Map<String, MessageDigest> neededDigestAlgorithms(Collection<SignerInformation> signerInfos) {
        Map<String, MessageDigest> mdByOid = new LinkedHashMap<>();
        for (SignerInformation si : signerInfos) {
            String oid = si.getDigestAlgOID();
            if (oid == null || mdByOid.containsKey(oid)) {
                continue;
            }
            String jceName = DigestAlgorithms.jceName(oid);
            if (jceName == null) {
                continue;
            }
            try {
                mdByOid.put(oid, MessageDigest.getInstance(jceName, PROV));
            } catch (Exception e) {

            }
        }
        return mdByOid;
    }

    private static Collection<SignerInformation> bindDigests(
            Collection<SignerInformation> signerInfos, byte[] der, Map<String, byte[]> digestsByOid) {
        Map<String, Map<String, SignerInformation>> boundByOid = new HashMap<>();
        for (Map.Entry<String, byte[]> e : digestsByOid.entrySet()) {
            CMSSignedData keyed;
            try {
                keyed = new CMSSignedData(e.getValue(), der);
            } catch (Exception ex) {
                throw new ContainerException(
                    Messages.get(MsgKey.PARSING_BIND_DIGEST_FAILED, ex.getMessage()), ex);
            }
            @SuppressWarnings("unchecked")
            Collection<SignerInformation> keyedSigners =
                (Collection<SignerInformation>) keyed.getSignerInfos().getSigners();
            Map<String, SignerInformation> bySignature = new HashMap<>();
            for (SignerInformation ksi : keyedSigners) {
                String key = signerInfoSignatureKey(ksi);
                if (key != null) {
                    bySignature.putIfAbsent(key, ksi);
                }
            }
            boundByOid.put(e.getKey(), bySignature);
        }

        List<SignerInformation> bound = new ArrayList<>(signerInfos.size());
        for (SignerInformation si : signerInfos) {
            Map<String, SignerInformation> bySignature = boundByOid.get(si.getDigestAlgOID());
            String key = bySignature == null ? null : signerInfoSignatureKey(si);
            SignerInformation replacement = key == null ? null : bySignature.get(key);
            bound.add(replacement != null ? replacement : si);
        }
        return bound;
    }

    private static String signerInfoSignatureKey(SignerInformation si) {
        byte[] sig = si.getSignature();
        return sig == null ? null : Base64.getEncoder().encodeToString(sig);
    }

    private static List<String> fileOrderSignatureKeys(byte[] der) {
        try {
            var asn1 = new ASN1InputStream(der).readObject();
            ContentInfo outer = ContentInfo.getInstance(asn1);
            SignedData signedData = SignedData.getInstance(outer.getContent());
            ASN1Set rawSignerInfos = signedData.getSignerInfos();
            List<String> out = new ArrayList<>();
            for (int i = 0; i < rawSignerInfos.size(); i++) {
                String key = null;
                try {
                    SignerInfo raw = SignerInfo.getInstance(rawSignerInfos.getObjectAt(i));
                    byte[] sig = raw.getEncryptedDigest().getOctets();
                    key = Base64.getEncoder().encodeToString(sig);
                } catch (Exception ignored) {

                }
                out.add(key);
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static List<ParsedSigner> reorderToFileOrder(
            List<ParsedSigner> signers, List<String> bcKeys, List<String> fileKeys) {
        if (fileKeys.size() != signers.size()) {
            return signers;
        }
        List<ParsedSigner> remaining = new ArrayList<>(signers);
        List<String> remainingKeys = new ArrayList<>(bcKeys);
        List<ParsedSigner> reordered = new ArrayList<>(signers.size());
        for (String want : fileKeys) {
            int foundIdx = -1;
            if (want != null) {
                for (int i = 0; i < remaining.size(); i++) {
                    if (want.equals(remainingKeys.get(i))) {
                        foundIdx = i;
                        break;
                    }
                }
            }
            if (foundIdx >= 0) {
                reordered.add(remaining.remove(foundIdx));
                remainingKeys.remove(foundIdx);
            }
        }
        reordered.addAll(remaining); 
        return reordered;
    }

    private static ParsedSigner withIndex(ParsedSigner ps, int newIndex) {
        return new ParsedSigner(
            newIndex, ps.certificate(), ps.keyUsage(), ps.signingTime(), ps.tstGenTime(),
            ps.hasTimestamp(), ps.hasRevocationValues(), ps.tsaTimestampingEkuOk(),
            ps.chain(), ps.archive(), ps.signerCertRaw(), ps.signingCertHashAlg(), ps.signingCertHash(),
            ps.tsaCertRaw(), ps.tsaCertsRaw(), ps.tstTokenDer(), ps.signatureValue(),
            ps.tstImprintAlg(), ps.tstImprintHash(), ps.archiveMarks(), ps.signerInfo(),
            ps.missingBbAttrs(), ps.tstCrlBlobs());
    }

    private static List<String> missingMandatoryBbAttrs(Collection<SignerInformation> signerInfos) {
        Set<String> missingAnywhere = new HashSet<>();
        for (SignerInformation si : signerInfos) {
            missingAnywhere.addAll(missingMandatoryBbAttrs(si.getSignedAttributes()));
        }

        List<String> missing = new ArrayList<>();
        for (MandatoryBbAttr m : MANDATORY_BB_ATTRS) {
            if (missingAnywhere.contains(m.name())) {
                missing.add(m.name());
            }
        }
        return missing;
    }

    private static List<String> missingMandatoryBbAttrs(AttributeTable at) {
        List<String> missing = new ArrayList<>();
        for (MandatoryBbAttr m : MANDATORY_BB_ATTRS) {
            if (at == null || at.get(m.oid()) == null) {
                missing.add(m.name());
            }
        }
        return missing;
    }

    static String cadesLevel(
            boolean hasTimestamp, boolean hasRevocation, boolean hasArchive, List<String> missingBb) {
        if (!missingBb.isEmpty()) {
            return Messages.get(MsgKey.PARSING_CADES_LEVEL_NOT_BB, String.join(", ", missingBb));
        }

        if (hasTimestamp && hasRevocation) {
            return hasArchive
                ? Messages.get(MsgKey.PARSING_CADES_LEVEL_LTA)
                : Messages.get(MsgKey.PARSING_CADES_LEVEL_LT);
        }
        if (hasTimestamp) {
            return Messages.get(MsgKey.PARSING_CADES_LEVEL_T);
        }
        return Messages.get(MsgKey.PARSING_CADES_LEVEL_BB);
    }

    private static X509Certificate resolveSignerCert(CertStore certStore, SignerInformation si) {
        try {
            Collection<? extends java.security.cert.Certificate> found =
                certStore.getCertificates(si.getSID());
            return found.isEmpty() ? null : (X509Certificate) found.iterator().next();
        } catch (Exception e) {
            return null;
        }
    }

    public static List<Certificate> resolveChain(
            X509Certificate signerCert, Map<X500Principal, X509Certificate> bySubject) {
        if (signerCert == null) {
            return List.of();
        }
        List<Certificate> chain = new ArrayList<>();
        Set<X500Principal> seen = new HashSet<>();
        seen.add(signerCert.getSubjectX500Principal());
        X509Certificate current = signerCert;
        while (!current.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
            X509Certificate parent = bySubject.get(current.getIssuerX500Principal());
            if (parent == null || seen.contains(parent.getSubjectX500Principal())) {
                break;
            }
            chain.add(certificateFields(parent));
            seen.add(parent.getSubjectX500Principal());
            current = parent;
        }
        return chain;
    }

    public static Certificate certificateFields(X509Certificate cert) {
        X509Name subject = x509Name(cert.getSubjectX500Principal());
        KeyUsageInfo ku = keyUsageInfo(cert);

        List<String> sortedOids = new ArrayList<>(KzEkuRoles.ROLES.keySet());
        sortedOids.sort(Comparator.comparingInt(String::length));
        List<String> subjectRoles = new ArrayList<>();
        for (String oid : sortedOids) {
            if (ku.extUsages().contains(oid)) {
                subjectRoles.add(KzEkuRoles.ROLES.get(oid));
            }
        }

        return new Certificate(
            firstValue(subject, X509Name.CN),
            stripPrefix(firstValue(subject, X509Name.SERIALNUMBER), "IIN"),
            extractBin(subject),
            firstValue(subject, X509Name.O),
            cert.getSerialNumber().toString(16),
            issuerHumanFriendly(cert),
            keyAlgorithm(cert),
            policyOids(cert),
            subjectRoles,
            cert.getNotBefore().toInstant(),
            cert.getNotAfter().toInstant());
    }

    private static X509Name x509Name(X500Principal principal) {
        try {
            ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(principal.getEncoded()).readObject();
            return X509Name.getInstance(seq);
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static String firstValue(X509Name name, DERObjectIdentifier oid) {
        if (name == null) {
            return null;
        }
        var values = name.getValues(oid);
        return values.isEmpty() ? null : (String) values.get(0);
    }

    private static String stripPrefix(String value, String prefix) {
        if (value != null && value.startsWith(prefix)) {
            return value.substring(prefix.length());
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private static String extractBin(X509Name name) {
        if (name == null) {
            return null;
        }
        List<String> candidates = new ArrayList<>();
        for (Object v : name.getValues(X509Name.OU)) {
            candidates.add((String) v);
        }
        for (Object v : name.getValues(OID_ORGANIZATION_IDENTIFIER)) {
            candidates.add((String) v);
        }
        for (String value : candidates) {
            if (value != null && value.startsWith("BIN")) {
                String rest = value.substring(3);
                if (!rest.isEmpty() && rest.chars().allMatch(Character::isDigit)) {
                    return rest;
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static String issuerHumanFriendly(X509Certificate cert) {
        return humanFriendlyName(cert.getIssuerX500Principal());
    }

    @SuppressWarnings("unchecked")
    private static String humanFriendlyName(X500Principal principal) {
        X509Name name = x509Name(principal);
        if (name == null) {
            return null;
        }
        var oids = name.getOIDs();
        var values = name.getValues();
        Map<String, Object> data = new LinkedHashMap<>();
        String lastField = null;
        for (int i = 0; i < oids.size(); i++) {
            DERObjectIdentifier oid = (DERObjectIdentifier) oids.get(i);
            String label = FRIENDLY_LABELS.getOrDefault(oid.getId(), oid.getId());
            Object value = values.get(i);
            lastField = label;
            Object existing = data.get(label);
            if (existing == null && !data.containsKey(label)) {
                data.put(label, value);
            } else {
                List<Object> list;
                if (existing instanceof List) {
                    list = (List<Object>) existing;
                } else {
                    list = new ArrayList<>();
                    list.add(existing);
                    data.put(label, list);
                }
                list.add(value);
            }
        }

        List<String> keys = new ArrayList<>(data.keySet());
        if ("Country".equals(lastField)) {
            Collections.reverse(keys);
        }
        List<String> toJoin = new ArrayList<>();
        for (String key : keys) {
            toJoin.add(key + ": " + recursiveHumanize(data.get(key)));
        }
        boolean hasComma = toJoin.stream().anyMatch(s -> s.indexOf(',') >= 0);
        String separator = hasComma ? "; " : ", ";
        Collections.reverse(toJoin);
        return String.join(separator, toJoin);
    }

    @SuppressWarnings("unchecked")
    private static String recursiveHumanize(Object value) {
        if (value instanceof List) {
            List<Object> list = (List<Object>) value;
            List<String> parts = new ArrayList<>();
            for (Object v : list) {
                parts.add(recursiveHumanize(v));
            }
            Collections.reverse(parts);
            return String.join(", ", parts);
        }
        return String.valueOf(value);
    }

    private static final Map<String, String> FRIENDLY_LABELS = Map.ofEntries(
        Map.entry(X509Name.CN.getId(), "Common Name"),
        Map.entry(X509Name.C.getId(), "Country"),
        Map.entry(X509Name.O.getId(), "Organization"),
        Map.entry(X509Name.OU.getId(), "Organizational Unit"),
        Map.entry(X509Name.ST.getId(), "State/Province"),
        Map.entry(X509Name.L.getId(), "Locality"),
        Map.entry(X509Name.SERIALNUMBER.getId(), "Serial Number"),
        Map.entry(X509Name.SURNAME.getId(), "Surname"),
        Map.entry(X509Name.GIVENNAME.getId(), "Given Name"));

    private static KeyAlgorithm keyAlgorithm(X509Certificate cert) {
        return KeyAlgorithm.of(cert);
    }

    private static List<String> policyOids(X509Certificate cert) {
        try {
            byte[] extValue = cert.getExtensionValue("2.5.29.32");
            if (extValue == null) {
                return List.of();
            }
            ASN1OctetString outer =
                ASN1OctetString.getInstance(new ASN1InputStream(extValue).readObject());
            ASN1Sequence seq =
                (ASN1Sequence) new ASN1InputStream(outer.getOctets()).readObject();
            List<String> out = new ArrayList<>();
            var e = seq.getObjects();
            while (e.hasMoreElements()) {
                PolicyInformation pi = PolicyInformation.getInstance(e.nextElement());
                out.add(pi.getPolicyIdentifier().getId());
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    public static KeyUsageInfo keyUsageInfo(X509Certificate cert) {
        Set<String> usages = new HashSet<>();
        boolean[] ku = cert.getKeyUsage();
        if (ku != null) {
            String[] names = {
                "digital_signature", "non_repudiation", "key_encipherment",
                "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
                "encipher_only", "decipher_only",
            };
            for (int i = 0; i < ku.length && i < names.length; i++) {
                if (ku[i]) {
                    usages.add(names[i]);
                }
            }
        }
        Set<String> extUsages = new HashSet<>();
        try {
            List<String> eku = cert.getExtendedKeyUsage();
            if (eku != null) {
                extUsages.addAll(eku);
            }
        } catch (CertificateParsingException ignored) {

        }
        return new KeyUsageInfo(usages, extUsages);
    }

    private static Instant signedAttrTime(SignerInformation si) {
        AttributeTable at = si.getSignedAttributes();
        if (at == null) {
            return null;
        }
        Attribute a = at.get(CMSAttributes.signingTime);
        if (a == null) {
            return null;
        }
        ASN1Set values = a.getAttrValues();
        if (values.size() == 0) {
            return null;
        }
        return timeToInstant(values.getObjectAt(0));
    }

    private static Instant timeToInstant(Object value) {
        try {
            if (value instanceof DERUTCTime t) {
                return t.getAdjustedDate().toInstant();
            }
            if (value instanceof DERGeneralizedTime t) {
                return t.getDate().toInstant();
            }
        } catch (Exception ignored) {

        }
        return null;
    }

    private static boolean hasUnsignedAttr(SignerInformation si, DERObjectIdentifier oid) {
        AttributeTable ut = si.getUnsignedAttributes();
        if (ut == null) {
            return false;
        }
        return ut.getAll(oid).size() > 0;
    }

    private record TstInfo(
            Instant genTime, boolean present, Boolean tsaEkuOk, byte[] tokenDer,
            X509Certificate tsaCert, List<X509Certificate> tsaCerts,
            String imprintAlg, byte[] imprintHash, List<byte[]> crlBlobs) {

        static TstInfo absent() {
            return new TstInfo(null, false, null, null, null, List.of(), null, null, List.of());
        }
    }

    private static TstInfo timestampFromUnsigned(SignerInformation si) {
        AttributeTable ut = si.getUnsignedAttributes();
        if (ut == null) {
            return TstInfo.absent();
        }
        Attribute a = ut.get(OID_SIGNATURE_TS_TOKEN);
        if (a == null) {
            return TstInfo.absent();
        }
        ASN1Set values = a.getAttrValues();
        if (values.size() == 0) {
            return new TstInfo(null, true, null, null, null, List.of(), null, null, List.of());
        }
        try {
            Object value = values.getObjectAt(0);
            byte[] tokenDer = ((kz.gov.pki.kalkan.asn1.ASN1Encodable) value).getDEREncoded();

            List<byte[]> tokenCrlBlobs = signedDataContext(tokenDer).crlBlobs();
            ContentInfo ci = ContentInfo.getInstance(value);
            TimeStampToken tst = new TimeStampToken(ci);
            var genTimeDate = tst.getTimeStampInfo().getGenTime();
            Instant genTime = genTimeDate != null ? genTimeDate.toInstant() : null;
            String imprintAlg = tst.getTimeStampInfo().getMessageImprintAlgOID();
            byte[] imprintHash = tst.getTimeStampInfo().getMessageImprintDigest();

            Boolean ekuOk = null;
            X509Certificate tsaCert = null;
            List<X509Certificate> tsaCerts = List.of();
            CMSSignedData tstCms = new CMSSignedData(ci);
            @SuppressWarnings("unchecked")
            Collection<SignerInformation> tstSigners =
                (Collection<SignerInformation>) tstCms.getSignerInfos().getSigners();
            if (!tstSigners.isEmpty()) {
                SignerInformation tstSi = tstSigners.iterator().next();
                CertStore tcs = tstCms.getCertificatesAndCRLs("Collection", PROV);
                tsaCerts = allCertsOf(tcs);
                Collection<? extends java.security.cert.Certificate> found =
                    tcs.getCertificates(tstSi.getSID());
                if (!found.isEmpty()) {
                    tsaCert = (X509Certificate) found.iterator().next();
                    try {
                        List<String> eku = tsaCert.getExtendedKeyUsage();
                        ekuOk = eku != null && eku.contains(OID_KP_TIME_STAMPING);
                    } catch (CertificateParsingException e) {
                        ekuOk = null;
                    }
                }
            }
            return new TstInfo(genTime, true, ekuOk, tokenDer, tsaCert, tsaCerts, imprintAlg, imprintHash,
                tokenCrlBlobs);
        } catch (Exception e) {
            return new TstInfo(null, true, null, null, null, List.of(), null, null, List.of());
        }
    }

    private static List<X509Certificate> allCertsOf(CertStore certStore) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        for (java.security.cert.Certificate c : certStore.getCertificates(null)) {
            out.add((X509Certificate) c);
        }
        return out;
    }

    private record EssBinding(String alg, byte[] hash) {
        static final EssBinding NONE = new EssBinding(null, null);
    }

    private static EssBinding signingCertificateBinding(SignerInformation si) {
        AttributeTable at = si.getSignedAttributes();
        if (at == null) {
            return EssBinding.NONE;
        }
        Attribute a = at.get(OID_SIGNING_CERTIFICATE_V2);
        if (a == null || a.getAttrValues().size() == 0) {
            return EssBinding.NONE;
        }
        try {
            var scv2 = kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2.getInstance(
                a.getAttrValues().getObjectAt(0));
            var certs = scv2.getCerts();
            if (certs.length == 0) {
                return EssBinding.NONE;
            }
            var essId = certs[0];
            return new EssBinding(essId.getHashAlgorithm().getObjectId().getId(), essId.getCertHash());
        } catch (Exception e) {
            return EssBinding.NONE;
        }
    }

    private record SignedDataContext(byte[] eContentTypeDer, List<byte[]> crlBlobs) {
    }

    private static SignedDataContext signedDataContext(byte[] der) {
        try {
            var asn1 = new kz.gov.pki.kalkan.asn1.ASN1InputStream(der).readObject();
            ContentInfo outer = ContentInfo.getInstance(asn1);
            var signedData = kz.gov.pki.kalkan.asn1.cms.SignedData.getInstance(outer.getContent());
            byte[] eContentTypeDer = signedData.getEncapContentInfo().getContentType().getDEREncoded();
            List<byte[]> crlBlobs = new ArrayList<>();
            ASN1Set crls = signedData.getCRLs();
            if (crls != null) {
                for (int i = 0; i < crls.size(); i++) {
                    crlBlobs.add(((kz.gov.pki.kalkan.asn1.ASN1Encodable) crls.getObjectAt(i)).getDEREncoded());
                }
            }
            return new SignedDataContext(eContentTypeDer, crlBlobs);
        } catch (Exception e) {
            return new SignedDataContext(null, List.of());
        }
    }

    private record ArchiveData(ArchiveTimestampInfo info, List<ArchiveTs.ParsedArchiveTimestamp> marks) {
    }

    private static ArchiveData archiveData(SignerInformation si, List<X509Certificate> containerCerts,
                                           SignedDataContext ctx) {
        AttributeTable ut = si.getUnsignedAttributes();
        if (ut == null) {
            return new ArchiveData(ArchiveTimestampInfo.none(), List.of());
        }
        List<Object> v3Values = allAttributeValues(ut, OID_ARCHIVE_TS_V3);
        int legacyCount = allAttributeValues(ut, OID_ARCHIVE_TS_V1).size()
            + allAttributeValues(ut, OID_ARCHIVE_TS_V2).size();
        Instant lastGenTime = null;
        if (!v3Values.isEmpty()) {
            lastGenTime = tryParseTstGenTime(v3Values.get(v3Values.size() - 1));
        }
        List<ArchiveTs.ParsedArchiveTimestamp> marks = ArchiveTs.parseArchiveTimestamps(
            si, containerCerts, ctx.crlBlobs(), ctx.eContentTypeDer());
        return new ArchiveData(
            new ArchiveTimestampInfo(v3Values.size(), legacyCount, lastGenTime), marks);
    }

    private static List<Object> allAttributeValues(AttributeTable ut, DERObjectIdentifier oid) {
        List<Object> out = new ArrayList<>();
        ASN1EncodableVector all = ut.getAll(oid);
        for (int i = 0; i < all.size(); i++) {
            Attribute a = (Attribute) all.get(i);
            ASN1Set values = a.getAttrValues();
            for (int j = 0; j < values.size(); j++) {
                out.add(values.getObjectAt(j));
            }
        }
        return out;
    }

    private static Instant tryParseTstGenTime(Object value) {
        try {
            ContentInfo ci = ContentInfo.getInstance(value);
            TimeStampToken tst = new TimeStampToken(ci);
            var genTime = tst.getTimeStampInfo().getGenTime();
            return genTime != null ? genTime.toInstant() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isAsciiWhitespace(byte b) {
        return b == ' ' || b == '\t' || b == '\r' || b == '\n';
    }

    private static boolean matches(byte[] raw, int from, String ascii) {
        byte[] pattern = ascii.getBytes(StandardCharsets.US_ASCII);
        if (from + pattern.length > raw.length) {
            return false;
        }
        for (int i = 0; i < pattern.length; i++) {
            if (raw[from + i] != pattern[i]) {
                return false;
            }
        }
        return true;
    }

    private static String stripAllWhitespace(byte[] raw, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < raw.length; i++) {
            byte b = raw[i];
            if (!isAsciiWhitespace(b)) {
                sb.append((char) (b & 0xFF));
            }
        }
        return sb.toString();
    }

    private static byte[] pemUnarmor(byte[] raw, int from) {
        String text = new String(raw, from, raw.length - from, StandardCharsets.US_ASCII);
        int beginIdx = text.indexOf("-----BEGIN");
        if (beginIdx < 0) {
            throw new ContainerException(Messages.get(MsgKey.PARSING_PEM_NO_BEGIN));
        }
        int headerEnd = text.indexOf('\n', beginIdx);
        if (headerEnd < 0) {
            throw new ContainerException(Messages.get(MsgKey.PARSING_PEM_BAD_HEADER));
        }
        int endIdx = text.indexOf("-----END", headerEnd);
        if (endIdx < 0) {
            throw new ContainerException(Messages.get(MsgKey.PARSING_PEM_NO_END));
        }
        String body = text.substring(headerEnd + 1, endIdx);
        String cleaned = body.replaceAll("\\s+", "");
        return Base64.getDecoder().decode(cleaned);
    }
}
