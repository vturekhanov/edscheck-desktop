package kz.edscheck.xml;

import static kz.edscheck.provider.jce.JceVerificationProvider.buildPath;
import static kz.edscheck.provider.jce.JceVerificationProvider.resolveAnchor;

import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import kz.edscheck.domain.Stage;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.OnlineRevocationRequest;
import kz.edscheck.provider.jce.EmbeddedRevocation;
import kz.edscheck.provider.jce.JceVerificationProvider.AnchorInfo;
import kz.edscheck.trust.ActiveBackend;
import kz.edscheck.trust.ManifestTrust;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;

public final class XmlOnlineRequests {
    private XmlOnlineRequests() {
    }

    public static List<OnlineRevocationRequest> collect(VerificationRequest request, byte[] container) {
        try {
            List<X509Certificate> trust = ManifestTrust.loadCertificates(request.trust().roots());
            boolean ignoreTruststore = request.ignoreTruststore();
            String crlPath = request.trust().crls().isEmpty() ? null : request.trust().crls().get(0);

            Document doc = XmlFormatDetector.parseSecurely(container);
            DetectedXml detected = XmlFormatDetector.detect(doc);

            List<OnlineRevocationRequest> requests = new ArrayList<>();
            if (detected.format() == XmlContainerFormat.XMLESF) {
                EsfInvoice invoice = EsfParser.parse(doc);
                X509Certificate signerCert = invoice.certificateRaw();
                if (signerCert == null) {
                    return List.of();
                }
                List<X509Certificate> containerCerts = List.of(signerCert);
                if (!resolveAnchor(signerCert, containerCerts, trust, ignoreTruststore).anchored()) {
                    return List.of();
                }
                String label = Messages.get(MsgKey.PROVIDER_LABEL_SIGNATURE, 1);
                addSharedTargetRequest(requests, signerCert, List.of(), List.of(), crlPath, containerCerts, trust,
                    label, 0, Stage.REVOCATION);
                addCaPathRequests(requests, signerCert, containerCerts, trust, Instant.now(), ignoreTruststore,
                    List.of(), List.of(), crlPath, label, 0, Stage.CHAIN);
                return requests;
            }

            for (ParsedXmlSignature ps : detected.signatures()) {
                X509Certificate signerCert = ps.certificateRaw();
                if (signerCert == null) {
                    continue;
                }
                List<X509Certificate> containerCerts = ps.certificateValues().isEmpty()
                    ? List.of(signerCert)
                    : concatCert(signerCert, ps.certificateValues());
                if (!resolveAnchor(signerCert, containerCerts, trust, ignoreTruststore).anchored()) {
                    continue;
                }
                Instant refTime = peekGenTime(ps.signatureTimestampToken());
                String label = Messages.get(MsgKey.PROVIDER_LABEL_SIGNATURE, ps.index() + 1);

                addSharedTargetRequest(requests, signerCert, ps.ocspValues(), ps.crlValues(), crlPath, containerCerts,
                    trust, label, ps.index(), Stage.REVOCATION);
                addCaPathRequests(requests, signerCert, containerCerts, trust, refTime, ignoreTruststore,
                    ps.ocspValues(), ps.crlValues(), crlPath, label, ps.index(), Stage.CHAIN);

                if (ps.signatureTimestampToken() != null) {
                    XmlCrypto.TsaCertInfo tsaInfo = XmlCrypto.peekTsaCert(ps.signatureTimestampToken());
                    if (tsaInfo.tsaCert() != null) {
                        List<X509Certificate> tsaPool = new ArrayList<>(containerCerts);
                        tsaPool.addAll(tsaInfo.tsaCerts());
                        String tsaLabel = label + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX);
                        addSharedTargetRequest(requests, tsaInfo.tsaCert(), ps.ocspValues(), ps.crlValues(), crlPath,
                            tsaPool, trust, tsaLabel, ps.index(), Stage.TIMESTAMP);
                        addCaPathRequests(requests, tsaInfo.tsaCert(), tsaPool, trust, refTime, ignoreTruststore,
                            ps.ocspValues(), ps.crlValues(), crlPath, tsaLabel, ps.index(), Stage.TIMESTAMP);
                    }
                }

                Element qualifyingProperties = ps.qualifyingPropertiesPresent()
                    ? XmlSignatureParser.matchingQualifyingProperties(doc, ps.id()) : null;
                for (XmlArchiveTimestamp.MarkTarget mark
                        : XmlArchiveTimestamp.peekMarkTargets(qualifyingProperties, ps.ocspValues(), ps.crlValues())) {
                    List<X509Certificate> markPool = new ArrayList<>(containerCerts);
                    markPool.addAll(mark.tsaCerts());
                    String markLabel = label + Messages.get(MsgKey.PROVIDER_LABEL_ARCHIVE_MARK_SUFFIX, mark.position() + 1);
                    addSharedTargetRequest(requests, mark.tsaCert(), mark.ocspBag(), mark.crlBag(), crlPath, markPool,
                        trust, markLabel + Messages.get(MsgKey.PROVIDER_LABEL_TSA_CERT_SUFFIX), ps.index(),
                        Stage.ARCHIVE_TIMESTAMP);
                    addCaPathRequests(requests, mark.tsaCert(), markPool, trust, mark.genTime(), ignoreTruststore,
                        mark.ocspBag(), mark.crlBag(), crlPath, markLabel, ps.index(), Stage.ARCHIVE_TIMESTAMP);
                }
            }
            return requests;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static List<X509Certificate> concatCert(X509Certificate signerCert, List<X509Certificate> extra) {
        List<X509Certificate> result = new ArrayList<>(extra.size() + 1);
        result.add(signerCert);
        result.addAll(extra);
        return result;
    }

    private static Instant peekGenTime(byte[] tstDer) {
        if (tstDer == null) {
            return Instant.now();
        }
        try {
            org.bouncycastle.asn1.ASN1InputStream ain = new org.bouncycastle.asn1.ASN1InputStream(tstDer);
            org.bouncycastle.asn1.cms.ContentInfo ci =
                org.bouncycastle.asn1.cms.ContentInfo.getInstance(ain.readObject());
            org.bouncycastle.tsp.TimeStampToken tst = new org.bouncycastle.tsp.TimeStampToken(ci);
            var genTime = tst.getTimeStampInfo().getGenTime();
            return genTime == null ? Instant.now() : genTime.toInstant();
        } catch (Exception e) {
            return Instant.now();
        }
    }

    private static void addSharedTargetRequest(
            List<OnlineRevocationRequest> requests, X509Certificate target, List<byte[]> ocspBlobs,
            List<byte[]> crlBlobs, String crlPath, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, String label, int signerIndex, Stage stage) {
        X509Certificate issuerCert = kz.edscheck.provider.jce.JceVerificationProvider.findBySubject(
            target.getIssuerX500Principal(), trust, containerCerts);
        if (issuerCert != null) {
            for (byte[] der : ocspBlobs) {
                try {
                    Object obj = new OCSPResp(der).getResponseObject();
                    if (obj instanceof BasicOCSPResp basic && EmbeddedRevocation.matchesOcsp(basic, issuerCert, target)) {
                        return;
                    }
                } catch (Exception ignored) {

                }
            }
        }
        try {
            CertificateFactory cf = ActiveBackend.x509CertificateFactory();
            for (byte[] der : crlBlobs) {
                try {
                    X509CRL crl = (X509CRL) cf.generateCRL(new java.io.ByteArrayInputStream(der));
                    if (crl != null && EmbeddedRevocation.matchesCrl(crl, target)) {
                        return;
                    }
                } catch (Exception ignored) {

                }
            }
        } catch (Exception ignored) {

        }
        if (crlPath != null) {
            return;
        }
        addRequestForUncoveredTarget(requests, target, containerCerts, trust, label, signerIndex, stage);
    }

    private static void addRequestForUncoveredTarget(
            List<OnlineRevocationRequest> requests, X509Certificate target, List<X509Certificate> containerCerts,
            List<X509Certificate> trust, String label, int signerIndex, Stage stage) {
        X509Certificate issuer = kz.edscheck.provider.jce.JceVerificationProvider.findBySubject(
            target.getIssuerX500Principal(), trust, containerCerts);
        if (issuer == null) {
            return;
        }
        requests.add(new OnlineRevocationRequest(target, issuer, "2.16.840.1.101.3.4.2.1", label, signerIndex, stage));
    }

    private static void addCaPathRequests(
            List<OnlineRevocationRequest> requests, X509Certificate pathTarget,
            List<X509Certificate> containerCerts, List<X509Certificate> trust, Instant refTime,
            boolean ignoreTruststore, List<byte[]> ocspBlobs, List<byte[]> crlBlobs, String crlPath,
            String labelPrefix, int signerIndex, Stage stage) {
        List<X509Certificate> path;
        try {
            path = buildPath(pathTarget, containerCerts, trust, refTime, ignoreTruststore);
        } catch (Exception e) {
            return;
        }
        for (int i = 0; i < path.size(); i++) {
            X509Certificate ca = path.get(i);
            String caLabel = labelPrefix + Messages.get(MsgKey.PROVIDER_LABEL_INTERMEDIATE_CA_SUFFIX, i + 1);
            addSharedTargetRequest(requests, ca, ocspBlobs, crlBlobs, crlPath, containerCerts, trust, caLabel,
                signerIndex, stage);
        }
    }
}
