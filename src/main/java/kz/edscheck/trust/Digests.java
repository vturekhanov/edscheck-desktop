package kz.edscheck.trust;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Collection;


public final class Digests {
    private static final int BUFFER_SIZE = 1 << 16;

    private Digests() {
    }

    
    public static long updateAll(InputStream in, Collection<MessageDigest> digests) throws IOException {
        byte[] buf = new byte[BUFFER_SIZE];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            for (MessageDigest md : digests) {
                md.update(buf, 0, n);
            }
            total += n;
        }
        return total;
    }

    
    public static long update(InputStream in, MessageDigest digest) throws IOException {
        return updateAll(in, java.util.List.of(digest));
    }
}
