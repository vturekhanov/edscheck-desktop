package kz.edscheck.gui.kalkan;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.function.UnaryOperator;
import java.util.jar.JarFile;

import kz.edscheck.trust.KalkanJar;
import kz.edscheck.trust.KalkanJarException;

public final class KalkanResolver {

    public static final String STORAGE_FILENAME = "kalkancrypt-0.7.6-certified.jar";

    private KalkanResolver() {
    }

    public sealed interface Resolution {

        record AlreadyOnClasspath() implements Resolution {
        }

        record Appended(Path jarPath) implements Resolution {
        }

        record NotFound(List<Path> candidates) implements Resolution {
        }

        record AgentUnavailable() implements Resolution {
        }
    }

    public static boolean alreadyOnClasspath() {
        try {
            Class.forName("kz.gov.pki.kalkan.jce.provider.KalkanProvider", false,
                KalkanResolver.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static Resolution resolve(Instrumentation instrumentation, List<Path> candidates) {
        if (alreadyOnClasspath()) {
            return new Resolution.AlreadyOnClasspath();
        }
        return resolveCandidates(instrumentation, candidates);
    }

    static Resolution resolveCandidates(Instrumentation instrumentation, List<Path> candidates) {
        if (instrumentation == null) {
            return new Resolution.AgentUnavailable();
        }
        for (Path candidate : candidates) {
            try {
                KalkanJar.verify(candidate);
            } catch (KalkanJarException e) {
                continue;
            }
            try {
                instrumentation.appendToSystemClassLoaderSearch(new JarFile(candidate.toFile()));
            } catch (IOException e) {
                continue;
            }
            System.setProperty(KalkanJar.PATH_PROPERTY, candidate.toString());
            return new Resolution.Appended(candidate);
        }
        return new Resolution.NotFound(candidates);
    }

    public static List<Path> defaultCandidates() {
        return List.of(storagePath());
    }

    public static Path storagePath() {
        return storageDir().resolve(STORAGE_FILENAME);
    }

    public static Path storageDir() {
        return storageDir(System::getenv);
    }

    static Path storageDir(UnaryOperator<String> env) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String home = System.getProperty("user.home", ".");
        if (os.contains("mac")) {
            return Path.of(home, "Library", "Application Support", "EDScheck");
        }
        if (os.contains("windows")) {
            String appData = env.apply("APPDATA");
            if (appData != null && !appData.isBlank()) {
                return Path.of(appData, "EDScheck");
            }
            return Path.of(home, "AppData", "Roaming", "EDScheck");
        }

        String xdgDataHome = env.apply("XDG_DATA_HOME");
        if (xdgDataHome != null && !xdgDataHome.isBlank()) {
            try {
                Path candidate = Path.of(xdgDataHome);
                if (candidate.isAbsolute()) {
                    return candidate.resolve("edscheck");
                }
            } catch (InvalidPathException e) {

            }
        }
        return Path.of(home, ".local", "share", "edscheck");
    }
}
