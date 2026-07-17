package kz.edscheck.domain;

import java.util.List;


public record TrustMaterial(List<String> roots, List<String> crls) {

    public TrustMaterial {
        roots = roots == null ? List.of() : List.copyOf(roots);
        crls = crls == null ? List.of() : List.copyOf(crls);
    }

    public static TrustMaterial empty() {
        return new TrustMaterial(List.of(), List.of());
    }
}
