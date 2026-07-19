package kz.edscheck.online;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.BERSet;
import kz.gov.pki.kalkan.asn1.DERIA5String;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.DERTaggedObject;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.x509.AccessDescription;
import kz.gov.pki.kalkan.asn1.x509.AuthorityInformationAccess;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.OCSPReq;
import kz.gov.pki.kalkan.ocsp.OCSPReqGenerator;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import kz.gov.pki.kalkan.tsp.TimeStampRequest;
import kz.gov.pki.kalkan.tsp.TimeStampRequestGenerator;
import kz.gov.pki.kalkan.tsp.TimeStampResponse;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.ParsedContainer;
import kz.edscheck.parsing.ParsedSigner;
import kz.edscheck.parsing.Parsing;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.DigestAlgorithms;

public final class Online {
    private static final String PROV = "KALKAN";
    private static final DERObjectIdentifier OID_REVOCATION_VALUES =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.24");
    private static final DERObjectIdentifier OID_SIGNATURE_TS_TOKEN =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.14");
    private static final String AIA_OID = "1.3.6.1.5.5.7.1.1";

    static {
        if (java.security.Security.getProvider(PROV) == null) {
            java.security.Security.addProvider(new KalkanProvider());
        }
    }

    private record Endpoint(List<Path> anchorCerts, String tsaUrl, String ocspUrlFallback,
                             String tsaReqPolicy) {
    }

    private static Map<String, Endpoint> endpoints() {
        Path certsDir = kz.edscheck.trust.CertsDir.resolve();
        return Map.of(
            "nca", new Endpoint(
                List.of(certsDir.resolve("prod").resolve("nca_gost_2022.pem")),
                "http://tsp.pki.gov.kz/", null, "1.2.398.3.3.2.6.4"),
            "btsd", new Endpoint(
                List.of(certsDir.resolve("prod").resolve("btsd_gost.cer")),
                "https://passport.aitu.io/pki/tsp", "https://passport.aitu.io/pki/ocsp", null));
    }

    public record AugmentedSigner(boolean tsaAdded, boolean ocspAdded) {
    }

    public record AugmentResult(byte[] bytes, Map<Integer, AugmentedSigner> augmented) {
    }

    private Online() {
    }

    public static AugmentResult maybeAugment(
            byte[] container, boolean crlGiven, Duration timeout, Trace trace) {
        ParsedContainer parsed = Parsing.parseContainer(container, List.of());

        Object asn1;
        try {
            asn1 = new ASN1InputStream(container).readObject();
        } catch (IOException e) {
            throw new OnlineException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()), e);
        }
        ContentInfo outer = ContentInfo.getInstance(asn1);
        SignedData signedData = SignedData.getInstance(outer.getContent());
        ASN1Set rawSignerInfos = signedData.getSignerInfos();

        Map<Integer, kz.gov.pki.kalkan.asn1.cms.SignerInfo> updated = new LinkedHashMap<>();
        Map<Integer, AugmentedSigner> augmentedInfo = new LinkedHashMap<>();
        for (ParsedSigner ps : parsed.signers()) {
            boolean needOcsp = !ps.hasRevocationValues() && !crlGiven;
            boolean needTsa = !ps.hasTimestamp();
            if (!needOcsp && !needTsa) {
                continue;
            }
            if (ps.signerCertRaw() == null) {
                trace.v(Messages.get(MsgKey.ONLINE_TRACE_SIGNER_CERT_MISSING, ps.index()));
                continue;
            }
            X509Certificate issuer = loadIssuerCert(ps.signerCertRaw());
            if (issuer == null) {
                trace.v(Messages.get(MsgKey.ONLINE_TRACE_ISSUER_MISSING, ps.index()));
                continue;
            }
            Endpoint endpoint = resolveEndpoint(issuer);
            if (endpoint == null) {
                trace.v(Messages.get(MsgKey.ONLINE_TRACE_ENDPOINT_UNSUPPORTED, ps.index()));
                continue;
            }

            SignerInformation current = ps.signerInfo();
            boolean changed = false;
            try {

                if (needTsa) {
                    current = augmentTsa(
                        ps.index(), current, endpoint.tsaUrl(), endpoint.tsaReqPolicy(), timeout, trace);
                    changed = true;
                }
                if (needOcsp) {
                    current = augmentOcsp(
                        ps.index(), current, ps.signerCertRaw(), issuer, endpoint, timeout, trace);
                    changed = true;
                }
            } catch (OnlineException e) {
                trace.v(Messages.get(MsgKey.ONLINE_TRACE_SKIP, ps.index(), e.getMessage()));
                continue;
            }
            if (changed) {
                updated.put(ps.index(), current.toSignerInfo());
                augmentedInfo.put(ps.index(), new AugmentedSigner(needTsa, needOcsp));
            }
        }

        if (updated.isEmpty()) {
            return new AugmentResult(container, Map.of());
        }

        byte[] newDer = rebuildContainer(outer, signedData, rawSignerInfos, updated);
        trace.v(Messages.get(MsgKey.ONLINE_TRACE_AUGMENTED_COUNT, updated.size(), rawSignerInfos.size()));
        return new AugmentResult(newDer, augmentedInfo);
    }

    public static X509Certificate loadIssuerCert(X509Certificate subject) {
        Path certsDir = kz.edscheck.trust.CertsDir.resolve();
        for (Path dir : List.of(certsDir.resolve("prod"), certsDir.resolve("test"))) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
                List<Path> paths = new ArrayList<>();
                stream.forEach(paths::add);
                paths.sort(Path::compareTo);
                for (Path p : paths) {
                    String name = p.getFileName().toString();
                    if (!(name.endsWith(".pem") || name.endsWith(".cer")
                            || name.endsWith(".crt") || name.endsWith(".der"))) {
                        continue;
                    }
                    X509Certificate cand = loadCertFile(p);
                    if (cand == null) {
                        continue;
                    }
                    if (cand.getSubjectX500Principal().equals(subject.getIssuerX500Principal())) {
                        return cand;
                    }
                }
            } catch (IOException ignored) {

            }
        }
        return null;
    }

    private static X509Certificate loadCertFile(Path path) {
        try (var in = Files.newInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", PROV);
            return (X509Certificate) cf.generateCertificate(in);
        } catch (Exception e) {
            return null;
        }
    }

    private static Endpoint resolveEndpoint(X509Certificate issuer) {
        byte[] issuerDer;
        try {
            issuerDer = issuer.getEncoded();
        } catch (Exception e) {
            return null;
        }
        for (Endpoint endpoint : endpoints().values()) {
            for (Path anchorPath : endpoint.anchorCerts()) {
                X509Certificate anchor = loadCertFile(anchorPath);
                if (anchor == null) {
                    continue;
                }
                try {
                    if (Arrays.equals(issuerDer, anchor.getEncoded())) {
                        return endpoint;
                    }
                } catch (Exception ignored) {

                }
            }
        }
        return null;
    }

    public static String aiaOcspUrl(X509Certificate cert) {
        byte[] raw = cert.getExtensionValue(AIA_OID);
        if (raw == null) {
            return null;
        }
        try {
            ASN1OctetString octets = (ASN1OctetString) new ASN1InputStream(raw).readObject();
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(
                new ASN1InputStream(octets.getOctets()).readObject());
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    GeneralName gn = ad.getAccessLocation();
                    if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return ((DERIA5String) gn.getName()).getString();
                    }
                }
            }
        } catch (Exception ignored) {

        }
        return null;
    }

    private static SignerInformation augmentOcsp(
            int index, SignerInformation si, X509Certificate subject, X509Certificate issuer,
            Endpoint endpoint, Duration timeout, Trace trace) {
        String url = aiaOcspUrl(subject);
        if (url == null) {
            url = endpoint.ocspUrlFallback();
        }
        if (url == null) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_OCSP_URL_NOT_FOUND));
        }
        String digestOid = si.getDigestAlgOID();
        trace.v(Messages.get(MsgKey.ONLINE_TRACE_OCSP_REQUEST, index, url, digestOid));
        BasicOCSPResp basic = requestOcsp(subject, issuer, digestOid, url, timeout);
        try {
            AttributeTable newTable = addRevocationValues(si.getUnsignedAttributes(), basic);
            trace.v(Messages.get(MsgKey.ONLINE_TRACE_REVOCATION_VALUES_ADDED, index));
            return SignerInformation.replaceUnsignedAttributes(si, newTable);
        } catch (Exception e) {
            throw new OnlineException(
                Messages.get(MsgKey.ONLINE_REVOCATION_VALUES_INSERT_FAILED, e.getMessage()), e);
        }
    }

    public static BasicOCSPResp requestOcsp(
            X509Certificate subject, X509Certificate issuer, String digestOid, String url, Duration timeout) {

        byte[] nonce = new byte[16];
        new java.security.SecureRandom().nextBytes(nonce);

        CertificateID certId;
        OCSPReq req;
        try {
            certId = new CertificateID(digestOid, issuer, subject.getSerialNumber());
            OCSPReqGenerator gen = new OCSPReqGenerator();
            gen.addRequest(certId);

            byte[] innerOctetDer = new DEROctetString(nonce).getDEREncoded();
            kz.gov.pki.kalkan.asn1.x509.X509Extension nonceExt =
                new kz.gov.pki.kalkan.asn1.x509.X509Extension(false, new DEROctetString(innerOctetDer));
            java.util.Hashtable<DERObjectIdentifier, kz.gov.pki.kalkan.asn1.x509.X509Extension> extMap =
                new java.util.Hashtable<>();
            extMap.put(kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce, nonceExt);
            gen.setRequestExtensions(new kz.gov.pki.kalkan.asn1.x509.X509Extensions(extMap));
            req = gen.generate();
        } catch (Exception e) {
            throw new OnlineException(
                Messages.get(MsgKey.ONLINE_OCSP_REQUEST_BUILD_FAILED, e.getMessage()), e);
        }

        byte[] responseBytes;
        try {
            responseBytes = post(url, req.getEncoded(),
                "application/ocsp-request", "application/ocsp-response", timeout);
        } catch (Exception e) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_OCSP_REQUEST_FAILED, e.getMessage()), e);
        }

        try {
            OCSPResp resp = new OCSPResp(responseBytes);
            if (resp.getStatus() != 0) {
                throw new OnlineException(Messages.get(MsgKey.ONLINE_OCSP_RESPONDER_STATUS, resp.getStatus()));
            }
            Object obj = resp.getResponseObject();
            if (!(obj instanceof BasicOCSPResp)) {
                throw new OnlineException(Messages.get(MsgKey.ONLINE_OCSP_UNEXPECTED_RESPONSE_TYPE, obj));
            }
            BasicOCSPResp basic = (BasicOCSPResp) obj;
            checkOcspNonce(basic, nonce);
            return basic;
        } catch (OnlineException e) {
            throw e;
        } catch (Exception e) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_OCSP_RESPONSE_PARSE_FAILED, e.getMessage()), e);
        }
    }

    public static AttributeTable addRevocationValues(AttributeTable existing, BasicOCSPResp basic) {
        try {
            byte[] revValuesDer = buildRevocationValues(basic);
            Object revValuesObj = new ASN1InputStream(revValuesDer).readObject();
            Attribute newAttr = new Attribute(OID_REVOCATION_VALUES, new DERSet((DEREncodable) revValuesObj));
            return replaceOrAdd(existing, newAttr);
        } catch (OnlineException e) {
            throw e;
        } catch (Exception e) {
            throw new OnlineException(
                Messages.get(MsgKey.ONLINE_REVOCATION_VALUES_BUILD_FAILED, e.getMessage()), e);
        }
    }

    static void checkOcspNonce(BasicOCSPResp basic, byte[] expectedNonce) throws Exception {
        byte[] gotNonce = null;
        kz.gov.pki.kalkan.asn1.x509.X509Extensions exts = basic.getResponseExtensions();
        if (exts != null) {
            kz.gov.pki.kalkan.asn1.x509.X509Extension ext =
                exts.getExtension(kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (ext != null) {
                byte[] innerDer = ext.getValue().getOctets();
                Object inner = new ASN1InputStream(innerDer).readObject();
                gotNonce = ((kz.gov.pki.kalkan.asn1.ASN1OctetString) inner).getOctets();
            }
        }
        if (!Arrays.equals(expectedNonce, gotNonce)) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_OCSP_NONCE_MISMATCH));
        }
    }

    private static byte[] buildRevocationValues(BasicOCSPResp basic) throws Exception {

        byte[] basicDer = basic.getEncoded();
        Object basicObj = new ASN1InputStream(basicDer).readObject();
        ASN1EncodableVector ocspValsVec = new ASN1EncodableVector();
        ocspValsVec.add((DEREncodable) basicObj);
        DERSequence ocspVals = new DERSequence(ocspValsVec);
        DERTaggedObject tagged = new DERTaggedObject(1, ocspVals);
        ASN1EncodableVector rvVec = new ASN1EncodableVector();
        rvVec.add(tagged);
        return new DERSequence(rvVec).getDEREncoded();
    }

    public static kz.gov.pki.kalkan.ocsp.BasicOCSPResp extractEmbeddedBasicOcsp(AttributeTable unsignedAttrs) {
        if (unsignedAttrs == null) {
            return null;
        }
        Attribute revAttr = unsignedAttrs.get(OID_REVOCATION_VALUES);
        if (revAttr == null) {
            return null;
        }
        try {
            kz.gov.pki.kalkan.asn1.ASN1Sequence revocationValues = kz.gov.pki.kalkan.asn1.ASN1Sequence.getInstance(
                revAttr.getAttrValues().getObjectAt(0));
            for (int i = 0; i < revocationValues.size(); i++) {
                Object element = revocationValues.getObjectAt(i);
                if (element instanceof kz.gov.pki.kalkan.asn1.ASN1TaggedObject tagged && tagged.getTagNo() == 1) {
                    kz.gov.pki.kalkan.asn1.ASN1Sequence ocspVals =
                        kz.gov.pki.kalkan.asn1.ASN1Sequence.getInstance(tagged, true);
                    if (ocspVals.size() == 0) {
                        return null;
                    }
                    kz.gov.pki.kalkan.asn1.ocsp.BasicOCSPResponse resp =
                        kz.gov.pki.kalkan.asn1.ocsp.BasicOCSPResponse.getInstance(ocspVals.getObjectAt(0));
                    return new kz.gov.pki.kalkan.ocsp.BasicOCSPResp(resp);
                }
            }
            return null;
        } catch (Exception e) {
            throw new OnlineException(
                Messages.get(MsgKey.ONLINE_EMBEDDED_OCSP_PARSE_FAILED, e.getMessage()), e);
        }
    }

    private static SignerInformation augmentTsa(
            int index, SignerInformation si, String tsaUrl, String reqPolicy, Duration timeout, Trace trace) {
        String digestOid = si.getDigestAlgOID();
        String jceName = DigestAlgorithms.jceName(digestOid);
        if (jceName == null) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_UNKNOWN_DIGEST_ALG, digestOid));
        }
        byte[] sigValue = si.getSignature();
        if (sigValue == null) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_SIGNATURE_VALUE_MISSING));
        }

        byte[] imprint;
        try {
            imprint = MessageDigest.getInstance(jceName, PROV).digest(sigValue);
        } catch (Exception e) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_IMPRINT_COMPUTE_FAILED, e.getMessage()), e);
        }

        trace.v(Messages.get(MsgKey.ONLINE_TRACE_TSA_REQUEST, index, tsaUrl, jceName));
        TimeStampToken token = requestTsa(imprint, digestOid, tsaUrl, reqPolicy, timeout);
        try {
            AttributeTable newTable = addSignatureTimestamp(si.getUnsignedAttributes(), token);
            trace.v(Messages.get(MsgKey.ONLINE_TRACE_TST_ADDED, index));
            return SignerInformation.replaceUnsignedAttributes(si, newTable);
        } catch (Exception e) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_TST_INSERT_FAILED, e.getMessage()), e);
        }
    }

    public static TimeStampToken requestTsa(
            byte[] imprint, String digestOid, String tsaUrl, String reqPolicy, Duration timeout) {

        TimeStampRequestGenerator tsGen = new TimeStampRequestGenerator();
        tsGen.setCertReq(true);
        if (reqPolicy != null) {
            tsGen.setReqPolicy(reqPolicy);
        }
        java.math.BigInteger nonce = new java.math.BigInteger(64, new java.security.SecureRandom());
        TimeStampRequest tsReq = tsGen.generate(digestOid, imprint, nonce);

        byte[] responseBytes;
        try {
            responseBytes = post(tsaUrl, tsReq.getEncoded(),
                "application/timestamp-query", "application/timestamp-reply", timeout);
        } catch (Exception e) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_TSA_REQUEST_FAILED, e.getMessage()), e);
        }

        try {
            TimeStampResponse tsResp = new TimeStampResponse(responseBytes);
            int status = tsResp.getStatus();
            if (status != 0 && status != 1) { 
                throw new OnlineException(
                    Messages.get(MsgKey.ONLINE_TSA_STATUS, status, tsResp.getStatusString()));
            }
            TimeStampToken token = tsResp.getTimeStampToken();
            if (token == null) {
                throw new OnlineException(Messages.get(MsgKey.ONLINE_TSA_NO_TOKEN, status));
            }

            tsResp.validate(tsReq);
            return token;
        } catch (OnlineException e) {
            throw e;
        } catch (Exception e) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_TSA_RESPONSE_PARSE_FAILED, e.getMessage()), e);
        }
    }

    public static AttributeTable addSignatureTimestamp(AttributeTable existing, TimeStampToken token) {
        try {
            byte[] tstDer = token.getEncoded();
            Object tstObj = new ASN1InputStream(tstDer).readObject();
            Attribute newAttr = new Attribute(OID_SIGNATURE_TS_TOKEN, new DERSet((DEREncodable) tstObj));
            return replaceOrAdd(existing, newAttr);
        } catch (OnlineException e) {
            throw e;
        } catch (Exception e) {
            throw new OnlineException(Messages.get(MsgKey.ONLINE_TST_BUILD_FAILED, e.getMessage()), e);
        }
    }

    private static AttributeTable replaceOrAdd(AttributeTable existing, Attribute newAttr) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (existing != null) {
            ASN1EncodableVector old = existing.toASN1EncodableVector();
            for (int i = 0; i < old.size(); i++) {
                Attribute a = Attribute.getInstance(old.get(i));
                if (!a.getAttrType().equals(newAttr.getAttrType())) {
                    vec.add(a);
                }
            }
        }
        vec.add(newAttr);
        return new AttributeTable(vec);
    }

    private static byte[] post(String url, byte[] body, String contentType, String accept,
                                Duration timeout) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .timeout(timeout)
            .header("Content-Type", contentType)
            .header("Accept", accept)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build();
        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() / 100 != 2) {
            throw new IOException(Messages.get(MsgKey.ONLINE_HTTP_ERROR, response.statusCode(), url));
        }
        return response.body();
    }

    private static byte[] rebuildContainer(
            ContentInfo outer, SignedData signedData, ASN1Set rawSignerInfos,
            Map<Integer, kz.gov.pki.kalkan.asn1.cms.SignerInfo> updated) {
        ASN1Set newSignerInfos = mergeSignerInfos(rawSignerInfos, updated);
        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), newSignerInfos);
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return newOuter.getDEREncoded();
    }

    public static ASN1Set mergeSignerInfos(
            ASN1Set existing, Map<Integer, kz.gov.pki.kalkan.asn1.cms.SignerInfo> updated) {
        int maxIndex = existing.size() - 1;
        for (int k : updated.keySet()) {
            maxIndex = Math.max(maxIndex, k);
        }
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i <= maxIndex; i++) {
            DEREncodable replacement = updated.get(i);
            if (replacement != null) {
                vec.add(replacement);
            } else if (i < existing.size()) {
                vec.add(existing.getObjectAt(i));
            } else {
                throw new OnlineException(Messages.get(MsgKey.ONLINE_MERGE_GAP, i));
            }
        }
        return new BERSet(vec);
    }
}
