package kz.edscheck.output;

import java.util.List;
import java.util.Map;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class JsonWriter {
    private static final String INDENT_UNIT = "  ";

    private JsonWriter() {
    }

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, 0);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object value, int level) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (value instanceof Number n) {
            sb.append(n.toString());
        } else if (value instanceof Map) {
            writeObject(sb, (Map<String, Object>) value, level);
        } else if (value instanceof List) {
            writeArray(sb, (List<Object>) value, level);
        } else {
            throw new IllegalArgumentException(
                Messages.get(MsgKey.JSON_WRITER_UNSUPPORTED_TYPE, value.getClass()));
        }
    }

    private static void writeObject(StringBuilder sb, Map<String, Object> map, int level) {
        if (map.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        String childIndent = INDENT_UNIT.repeat(level + 1);
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) {
                sb.append(",\n");
            }
            first = false;
            sb.append(childIndent);
            writeString(sb, entry.getKey());
            sb.append(": ");
            writeValue(sb, entry.getValue(), level + 1);
        }
        sb.append("\n").append(INDENT_UNIT.repeat(level)).append("}");
    }

    private static void writeArray(StringBuilder sb, List<Object> list, int level) {
        if (list.isEmpty()) {
            sb.append("[]");
            return;
        }
        sb.append("[\n");
        String childIndent = INDENT_UNIT.repeat(level + 1);
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(",\n");
            }
            first = false;
            sb.append(childIndent);
            writeValue(sb, item, level + 1);
        }
        sb.append("\n").append(INDENT_UNIT.repeat(level)).append("]");
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
