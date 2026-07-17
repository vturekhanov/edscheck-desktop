package kz.edscheck.provider;

import java.util.Set;


public record KeyUsageInfo(Set<String> usages, Set<String> extUsages) {

    public KeyUsageInfo {
        usages = usages == null ? Set.of() : Set.copyOf(usages);
        extUsages = extUsages == null ? Set.of() : Set.copyOf(extUsages);
    }

    public KeyUsageInfo() {
        this(Set.of(), Set.of());
    }
}
