package kz.edscheck.trust;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;


public final class KalkanJar {
    
    public static final String PATH_PROPERTY = "kz.edscheck.kalkanJar";

    
    public static final String EXPECTED_SHA256 =
        "efb86851e960542492dfa8f44ebf535d0c745904ddc547e5e82463ae86b1abda";

    private KalkanJar() {
    }

    
    public static Path resolveFromSystemProperty() throws KalkanJarException {
        String raw = System.getProperty(PATH_PROPERTY);
        if (raw == null || raw.isBlank()) {
            throw new KalkanJarException(
                Messages.get(MsgKey.KALKAN_JAR_PATH_PROPERTY_MISSING, PATH_PROPERTY));
        }
        return Paths.get(raw);
    }

    
    public static void verify(Path jarPath) throws KalkanJarException {
        if (!Files.isRegularFile(jarPath)) {
            throw new KalkanJarException(Messages.get(MsgKey.KALKAN_JAR_NOT_FOUND, jarPath));
        }
        String actual;
        try {
            actual = sha256Hex(jarPath);
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new KalkanJarException(
                Messages.get(MsgKey.KALKAN_JAR_SHA256_COMPUTE_FAILED, jarPath, e.getMessage()));
        }
        if (!actual.equalsIgnoreCase(EXPECTED_SHA256)) {
            throw new KalkanJarException(
                Messages.get(MsgKey.KALKAN_JAR_SHA256_MISMATCH, jarPath, EXPECTED_SHA256, actual));
        }
    }

    
    public static Path resolveAndVerify() throws KalkanJarException {
        Path jarPath = resolveFromSystemProperty();
        verify(jarPath);
        return jarPath;
    }

    
    public static void ensureSecurityProviderRegistered() {
        if (Security.getProvider("KALKAN") == null) {
            Security.addProvider(new kz.gov.pki.kalkan.jce.provider.KalkanProvider());
        }
    }

    private static String sha256Hex(Path path) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(path)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                digest.update(buf, 0, n);
            }
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : digest.digest()) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
