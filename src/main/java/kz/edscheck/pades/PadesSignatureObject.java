package kz.edscheck.pades;

public record PadesSignatureObject(
        String fieldName,
        String type,
        String subFilter,
        byte[] contents,
        int[] byteRange,
        String signingDate) {

    public static final String TYPE_SIGNATURE = "Sig";

    public static final String TYPE_ARCHIVE_TIMESTAMP = "DocTimeStamp";

    public static final String SUBFILTER_CADES_DETACHED = "ETSI.CAdES.detached";

    public static final String SUBFILTER_RFC3161 = "ETSI.RFC3161";

    public PadesSignatureObject {
        contents = contents == null ? new byte[0] : contents.clone();
        byteRange = byteRange == null ? new int[0] : byteRange.clone();
    }

    @Override
    public byte[] contents() {
        return contents.clone();
    }

    @Override
    public int[] byteRange() {
        return byteRange.clone();
    }

    public boolean isSignature() {
        return TYPE_SIGNATURE.equals(type);
    }

    public boolean isArchiveTimestamp() {
        return TYPE_ARCHIVE_TIMESTAMP.equals(type);
    }

    public int coveredEnd() {
        return byteRange.length == 4 ? byteRange[2] + byteRange[3] : -1;
    }

    public int gapStart() {
        return byteRange.length == 4 ? byteRange[1] : -1;
    }
}
