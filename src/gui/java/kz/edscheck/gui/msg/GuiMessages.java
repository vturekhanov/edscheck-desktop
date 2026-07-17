package kz.edscheck.gui.msg;

import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;


public final class GuiMessages {
    public static final Locale DEFAULT_LOCALE = Locale.of("ru");
    public static final List<String> SUPPORTED_LOCALES = List.of("ru");

    private static Locale currentLocale = DEFAULT_LOCALE;
    private static final Map<Locale, ResourceBundle> BUNDLES = new HashMap<>();

    private GuiMessages() {
    }

    public static void setLocale(Locale locale) {
        currentLocale = locale;
    }

    public static Locale locale() {
        return currentLocale;
    }

    private static ResourceBundle bundle() {
        return BUNDLES.computeIfAbsent(currentLocale,
            loc -> ResourceBundle.getBundle("kz.edscheck.gui.msg.messages", loc));
    }

    public static String get(GuiMsgKey key, Object... args) {
        if (args.length != key.argCount()) {
            
            
            throw new IllegalArgumentException(
                get(GuiMsgKey.MESSAGES_ARG_COUNT_MISMATCH, key, key.argCount(), args.length));
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
}
