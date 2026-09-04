package kz.edscheck.trust;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class LibraryJars {

    public static final String PATH_PROPERTY = "kz.edscheck.libDir";

    private static final Map<String, String> RUNTIME_PINS = Map.of(

        "pdfbox-3.0.7.jar",
        "7cefa717622330951b4343abf1e5d36bccb11f4ba245d78aaa73251d08fec623",
        "pdfbox-io-3.0.7.jar",
        "b9a838291978069086efbcd1f62b81b9e4a6016e61dd2c68104ee9f4c2ff997b",
        "commons-logging-1.4.0.jar",
        "d175dbd751dd782a63bde28c7a039520e971f25e84b79c19b8435edc3603e0dc",

        "flatlaf-3.7.2-no-natives.jar",
        "1ce575b402951759ac523e050038bb39b44445a5f1e27544f3d4c61013e3c3a4",

        "xmlsec-3.0.3.jar",
        "b23df0b77125345f549374a85ca93c74e09d548a6c92858923b9fd9a24d5188b",
        "slf4j-api-2.0.9.jar",
        "0818930dc8d7debb403204611691da58e49d42c50b6ffcfdce02dadb7c3c2b6c",
        "slf4j-nop-2.0.9.jar",
        "5612367b12bac3eacf4e6ff4e06ce5ba1c83c4d8d6d5e2ea5f924635717a6d83",

        "bcprov-jdk18on-1.85.2.jar",
        "986b0fb92ec10e0c66b43e036ce0077e6150cfaecd1db9fb92b56672e157afe5",
        "bcutil-jdk18on-1.85.jar",
        "590f55ed5d68529239898a4a5c4f730b6e37f45d1cfa3fbe51f8485abe32c42d",
        "bcpkix-jdk18on-1.85.jar",
        "c9f82b2d4e99c4bbdfccf684e52cc06ea06a0b567bfd0d08f9c5a3f417055996");

    private static final Map<String, String> TEST_ONLY_PINS = Map.of(
        "junit-platform-console-standalone-6.1.1.jar",
        "7b16416e5727c645105c31b533440397f20df68f6ae850c6bfd0ce1d88db66c3");

    private static final Map<String, String> NATIVE_LIB_PINS = Map.of(

        "flatlaf-3.7.2-macos-arm64.dylib",
        "2265193840cf441dbf6efde2cf4bde65f253b75ade1b3b61242d556e54146f9a",
        "flatlaf-3.7.2-linux-x86_64.so",
        "e1ec96c7f00c764206e5f55046de017ed28a2669afe4b469f883ea690fd1659a",

        "flatlaf-3.7.2-windows-x86_64.dll",
        "533407841892e294f70e4f1443ebddecbea83b7f0bd2af876181505073b677d5",

        "flatlaf-3.7.2-linux-arm64.so",
        "5cb60b7846f72ca5a3cb7936f1fb848c76e7eb047c959eeb4fbf6fec77c6fe57",
        "flatlaf-3.7.2-windows-arm64.dll",
        "1c63bac895f42bd873a6e643af8864b73a4ec3fb51620db2f60ca45ec589964a");

    private LibraryJars() {
    }

    public static Path resolveDirFromSystemProperty() throws LibraryJarException {
        String raw = System.getProperty(PATH_PROPERTY);
        if (raw == null || raw.isBlank()) {
            throw new LibraryJarException(
                Messages.get(MsgKey.LIBRARY_JARS_PATH_PROPERTY_MISSING, PATH_PROPERTY));
        }
        return Path.of(raw);
    }

    public static void verifyRuntime(Path libDir) throws LibraryJarException {
        verify(libDir, RUNTIME_PINS);
    }

    public static void verifyAll(Path libDir) throws LibraryJarException {
        verify(libDir, RUNTIME_PINS);
        verify(libDir, TEST_ONLY_PINS);
        verify(libDir, NATIVE_LIB_PINS);
    }

    private static void verify(Path libDir, Map<String, String> pins) throws LibraryJarException {
        for (Map.Entry<String, String> pin : pins.entrySet()) {
            Path jar = libDir.resolve(pin.getKey());
            if (!Files.isRegularFile(jar)) {
                throw new LibraryJarException(Messages.get(MsgKey.LIBRARY_JARS_NOT_FOUND, jar));
            }
            String actual;
            try {
                actual = sha256Hex(jar);
            } catch (IOException | NoSuchAlgorithmException e) {
                throw new LibraryJarException(
                    Messages.get(MsgKey.LIBRARY_JARS_SHA256_COMPUTE_FAILED, jar, e.getMessage()));
            }
            if (!actual.equalsIgnoreCase(pin.getValue())) {
                throw new LibraryJarException(
                    Messages.get(MsgKey.LIBRARY_JARS_SHA256_MISMATCH, jar, pin.getValue(), actual));
            }
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
