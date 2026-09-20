package kz.edscheck.pades;

import java.util.List;

public record PadesDssMaterial(List<byte[]> certs, List<byte[]> crls, List<byte[]> ocsps) {
    public PadesDssMaterial {
        certs = certs == null ? List.of() : List.copyOf(certs);
        crls = crls == null ? List.of() : List.copyOf(crls);
        ocsps = ocsps == null ? List.of() : List.copyOf(ocsps);
    }

    public boolean isEmpty() {
        return certs.isEmpty() && crls.isEmpty() && ocsps.isEmpty();
    }
}
