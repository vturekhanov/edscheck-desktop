package kz.edscheck.trust;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

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

    public static OutputStream sink(Collection<MessageDigest> digests) {
        return new OutputStream() {
            @Override
            public void write(int b) {
                for (MessageDigest md : digests) {
                    md.update((byte) b);
                }
            }

            @Override
            public void write(byte[] b, int off, int len) {
                for (MessageDigest md : digests) {
                    md.update(b, off, len);
                }
            }
        };
    }

    public static Map<String, byte[]> finish(Map<String, MessageDigest> mdByOid) {
        Map<String, byte[]> digestsByOid = new LinkedHashMap<>();
        for (Map.Entry<String, MessageDigest> e : mdByOid.entrySet()) {
            digestsByOid.put(e.getKey(), e.getValue().digest());
        }
        return digestsByOid;
    }

    public static Map<String, MessageDigest> forOids(Iterable<String> oids) {
        Map<String, MessageDigest> mdByOid = new LinkedHashMap<>();
        for (String oid : oids) {
            if (oid == null || mdByOid.containsKey(oid)) {
                continue;
            }
            String jceName = DigestAlgorithms.jceName(oid);
            if (jceName == null) {
                continue;
            }
            try {
                mdByOid.put(oid, MessageDigest.getInstance(jceName, ActiveBackend.current().jceProviderName()));
            } catch (Exception e) {

            }
        }
        return mdByOid;
    }
}
