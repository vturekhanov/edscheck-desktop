package kz.edscheck.msg;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

public final class Messages {

    public static final Locale DEFAULT_LOCALE = Locale.of("ru");

    public static final List<String> SUPPORTED_LOCALES = List.of("ru");

    private static Locale currentLocale = DEFAULT_LOCALE;
    private static final Map<Locale, ResourceBundle> BUNDLES = new HashMap<>();

    private Messages() {
    }

    public static void setLocale(Locale locale) {
        currentLocale = locale;
    }

    public static Locale locale() {
        return currentLocale;
    }

    private static ResourceBundle bundle() {
        return BUNDLES.computeIfAbsent(currentLocale,
            loc -> ResourceBundle.getBundle("kz.edscheck.msg.messages", loc));
    }

    public static String get(MsgKey key, Object... args) {
        if (args.length != key.argCount()) {

            throw new IllegalArgumentException(
                get(MsgKey.MESSAGES_ARG_COUNT_MISMATCH, key, key.argCount(), args.length));
        }
        String pattern = bundle().getString(key.key());
        if (args.length == 0) {
            return pattern;
        }
        Object[] strings = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            strings[i] = String.valueOf(args[i]);
        }
        return new MessageFormat(pattern, Locale.ROOT).format(strings);
    }

    public static String resource(String path) {
        try (InputStream in = Messages.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException(get(MsgKey.MESSAGES_RESOURCE_NOT_FOUND, path));
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
