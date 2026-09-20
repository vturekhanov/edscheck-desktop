package kz.edscheck.parsing;

import java.util.Arrays;
import java.util.List;

public final class DerSetOrder {
    private DerSetOrder() {
    }

    public static int compare(byte[] a, byte[] b) {
        int maxLen = Math.max(a.length, b.length);
        byte[] pa = Arrays.copyOf(a, maxLen); 
        byte[] pb = Arrays.copyOf(b, maxLen);
        for (int i = 0; i < maxLen; i++) {
            int x = pa[i] & 0xFF;
            int y = pb[i] & 0xFF;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return 0;
    }

    public static boolean isCanonicalOrder(List<byte[]> encodingsInFileOrder) {
        for (int i = 1; i < encodingsInFileOrder.size(); i++) {
            if (compare(encodingsInFileOrder.get(i - 1), encodingsInFileOrder.get(i)) > 0) {
                return false;
            }
        }
        return true;
    }
}
