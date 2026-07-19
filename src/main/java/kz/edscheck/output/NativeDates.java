package kz.edscheck.output;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NativeDates {
    private static final Pattern NATIVE_DT_RE =
        Pattern.compile("(\\d{14})GMT([+-])(\\d{2}):?(\\d{2})");
    private static final DateTimeFormatter DT_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx", Locale.ROOT);

    private NativeDates() {
    }

    public static String localize(String text) {
        if (text == null || !text.contains("GMT")) {
            return text;
        }
        Matcher m = NATIVE_DT_RE.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String stamp = m.group(1);
            String sign = m.group(2);
            int offH = Integer.parseInt(m.group(3));
            int offM = Integer.parseInt(m.group(4));
            LocalDateTime local = LocalDateTime.parse(
                stamp, DateTimeFormatter.ofPattern("yyyyMMddHHmmss", Locale.ROOT));
            ZoneOffset offset = ZoneOffset.ofHoursMinutes(
                "-".equals(sign) ? -offH : offH, "-".equals(sign) ? -offM : offM);
            Instant instant = OffsetDateTime.of(local, offset).toInstant();
            m.appendReplacement(sb, Matcher.quoteReplacement(fmtDt(instant)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String fmtDt(Instant value) {
        return value.atZone(ZoneId.systemDefault()).format(DT_FMT);
    }
}
