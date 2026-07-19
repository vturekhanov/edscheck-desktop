package kz.edscheck.trust;

import java.nio.file.Path;
import java.nio.file.Paths;

public final class CertsDir {

    public static final String PATH_PROPERTY = "kz.edscheck.certsDir";

    private CertsDir() {
    }

    public static Path resolve() {
        String raw = System.getProperty(PATH_PROPERTY);
        if (raw == null || raw.isBlank()) {
            return Paths.get("certs");
        }
        return Paths.get(raw);
    }
}
