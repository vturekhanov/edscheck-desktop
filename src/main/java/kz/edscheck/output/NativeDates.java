package kz.edscheck.output;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NativeDates {
    private static final Pattern NATIVE_DT_RE =
        Pattern.compile("(\\d{14})GMT([+-])(\\d{2}):?(\\d{2})");

    private static final Pattern JDK_DATE_TOSTRING_RE = Pattern.compile(
        "[A-Z][a-z]{2} ([A-Z][a-z]{2}) (\\d{2}) (\\d{2}):(\\d{2}):(\\d{2}) \\S+ (\\d{4})");
    private static final List<String> MONTH_ABBR = Arrays.asList(
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
    private static final DateTimeFormatter DT_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx", Locale.ROOT);

    private NativeDates() {
    }

    public static String localize(String text) {
        if (text == null) {
            return null;
        }
        String result = text;
        if (result.contains("GMT")) {
            result = localizeGmtStamps(result);
        }
        if (JDK_DATE_TOSTRING_RE.matcher(result).find()) {
            result = localizeJdkDateToString(result);
        }
        return result;
    }

    private static String localizeGmtStamps(String text) {
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

    private static String localizeJdkDateToString(String text) {
        Matcher m = JDK_DATE_TOSTRING_RE.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            int month = MONTH_ABBR.indexOf(m.group(1)) + 1;
            if (month == 0) {
                continue; 
            }
            int day = Integer.parseInt(m.group(2));
            int hh = Integer.parseInt(m.group(3));
            int mm = Integer.parseInt(m.group(4));
            int ss = Integer.parseInt(m.group(5));
            int year = Integer.parseInt(m.group(6));
            LocalDateTime local = LocalDateTime.of(year, month, day, hh, mm, ss);
            ZoneOffset offset = ZoneId.systemDefault().getRules().getOffset(local);
            m.appendReplacement(sb, Matcher.quoteReplacement(local.atOffset(offset).format(DT_FMT)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String fmtDt(Instant value) {
        return value.atZone(ZoneId.systemDefault()).format(DT_FMT);
    }
}
