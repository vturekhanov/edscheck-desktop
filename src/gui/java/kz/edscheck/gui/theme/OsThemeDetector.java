package kz.edscheck.gui.theme;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public final class OsThemeDetector {
    private static final int TIMEOUT_SECONDS = 2;

    private OsThemeDetector() {
    }

    public static OsTheme detect() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        try {
            if (os.contains("mac")) {
                return detectMac();
            }
            if (os.contains("linux")) {
                return detectLinuxGnome();
            }
            if (os.contains("windows")) {
                return detectWindows();
            }
        } catch (Exception e) {
            return OsTheme.LIGHT;
        }
        return OsTheme.LIGHT;
    }

    private static OsTheme detectMac() throws Exception {
        String out = run("defaults", "read", "-g", "AppleInterfaceStyle");
        return out != null && out.strip().equalsIgnoreCase("Dark") ? OsTheme.DARK : OsTheme.LIGHT;
    }

    private static OsTheme detectLinuxGnome() throws Exception {
        String colorScheme = run("gsettings", "get", "org.gnome.desktop.interface", "color-scheme");
        if (colorScheme != null && colorScheme.toLowerCase(Locale.ROOT).contains("dark")) {
            return OsTheme.DARK;
        }
        String gtkTheme = run("gsettings", "get", "org.gnome.desktop.interface", "gtk-theme");
        if (gtkTheme != null && gtkTheme.toLowerCase(Locale.ROOT).contains("dark")) {
            return OsTheme.DARK;
        }
        return OsTheme.LIGHT;
    }

    private static OsTheme detectWindows() throws Exception {
        String out = run("reg", "query",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "/v", "AppsUseLightTheme");
        return out != null && out.contains("0x0") ? OsTheme.DARK : OsTheme.LIGHT;
    }

    private static String run(String... command) throws Exception {
        Process proc = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean finished = proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            return null;
        }
        if (proc.exitValue() != 0) {
            return null;
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }
}
