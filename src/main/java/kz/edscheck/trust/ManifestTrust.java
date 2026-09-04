package kz.edscheck.trust;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import kz.edscheck.errors.OperationalException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class ManifestTrust {
    private static final Logger LOG = Logger.getLogger(ManifestTrust.class.getName());
    private static final Path MANIFEST_CERTS_PREFIX = Paths.get("certs");

    private ManifestTrust() {
    }

    public static List<String> trustedCerts(String ca, String env) {
        if ("fake".equals(ca)) {
            return List.of();
        }
        List<String> resolved = new ArrayList<>();
        for (String rel : manifestTrustedCertFiles(env)) {
            Path path = resolveCertPath(rel);
            if (Files.exists(path)) {
                resolved.add(path.toString());
            } else {
                LOG.warning(Messages.get(MsgKey.MANIFEST_TRUST_TRUSTED_CERT_NOT_FOUND, rel));
            }
        }
        return resolved;
    }

    private static Path resolveCertPath(String rel) {
        Path relPath = Paths.get(rel);
        Path tail = relPath.startsWith(MANIFEST_CERTS_PREFIX)
            ? MANIFEST_CERTS_PREFIX.relativize(relPath)
            : relPath;
        return CertsDir.resolve().resolve(tail);
    }

    @SuppressWarnings("unchecked")
    private static List<String> manifestTrustedCertFiles(String env) {
        Path manifestPath = CertsDir.resolve().resolve("MANIFEST.json");
        String json;
        try {
            json = Files.readString(manifestPath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new OperationalException(
                Messages.get(MsgKey.MANIFEST_TRUST_READ_FAILED, manifestPath, e.getMessage()), e);
        }
        Map<String, Object> data;
        try {
            data = (Map<String, Object>) Json.parse(json);
        } catch (RuntimeException e) {
            throw new OperationalException(
                Messages.get(MsgKey.MANIFEST_TRUST_PARSE_FAILED, manifestPath, e.getMessage()), e);
        }
        List<Object> certs = (List<Object>) data.getOrDefault("certs", List.of());
        List<String> out = new ArrayList<>();
        for (Object o : certs) {
            Map<String, Object> entry = (Map<String, Object>) o;
            if ("active".equals(entry.get("class"))
                    && env.equals(entry.get("env"))
                    && entry.get("file") != null) {
                out.add((String) entry.get("file"));
            }
        }
        return out;
    }

    public static List<X509Certificate> loadCertificates(List<String> paths) {
        List<X509Certificate> certs = new ArrayList<>();
        CertificateFactory cf;
        try {
            cf = ActiveBackend.x509CertificateFactory();
        } catch (Exception e) {
            throw new OperationalException(
                Messages.get(MsgKey.MANIFEST_TRUST_CERT_FACTORY_FAILED, e.getMessage()), e);
        }
        for (String path : paths) {
            try (InputStream in = Files.newInputStream(Paths.get(path))) {
                for (java.security.cert.Certificate c : cf.generateCertificates(in)) {
                    certs.add((X509Certificate) c);
                }
            } catch (Exception e) {
                LOG.log(Level.WARNING, Messages.get(MsgKey.MANIFEST_TRUST_CERT_PARSE_FAILED, path), e);
            }
        }
        return certs;
    }
}
