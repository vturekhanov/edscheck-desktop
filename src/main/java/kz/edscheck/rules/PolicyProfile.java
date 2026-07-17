package kz.edscheck.rules;

import java.time.Duration;
import java.util.Set;


public final class PolicyProfile {
    private final boolean requireTimestamp;
    private final Set<String> allowedKeyAlgorithms;
    private final boolean enforcePolicyOids;
    private final boolean requireNonRepudiation;
    
    private final Duration ocspMaxAge;
    
    private final boolean requireBbAttrs;

    public PolicyProfile() {
        this(false, Set.of(), false, true, Duration.ofMinutes(5), false);
    }

    public PolicyProfile(
            boolean requireTimestamp, Set<String> allowedKeyAlgorithms,
            boolean enforcePolicyOids, boolean requireNonRepudiation, Duration ocspMaxAge,
            boolean requireBbAttrs) {
        this.requireTimestamp = requireTimestamp;
        this.allowedKeyAlgorithms = allowedKeyAlgorithms == null ? Set.of() : Set.copyOf(allowedKeyAlgorithms);
        this.enforcePolicyOids = enforcePolicyOids;
        this.requireNonRepudiation = requireNonRepudiation;
        this.ocspMaxAge = ocspMaxAge;
        this.requireBbAttrs = requireBbAttrs;
    }

    
    public static PolicyProfile withOcspMaxAge(Duration ocspMaxAge) {
        return new PolicyProfile(false, Set.of(), false, true, ocspMaxAge, false);
    }

    public static PolicyProfile withRequireTimestamp(boolean requireTimestamp) {
        return new PolicyProfile(requireTimestamp, Set.of(), false, true, Duration.ofMinutes(5), false);
    }

    
    public static PolicyProfile withRequireBbAttrs(boolean requireBbAttrs) {
        return new PolicyProfile(false, Set.of(), false, true, Duration.ofMinutes(5), requireBbAttrs);
    }

    
    public static PolicyProfile ncaPolicy() {
        return new PolicyProfile();
    }

    public boolean requireTimestamp() {
        return requireTimestamp;
    }

    public boolean requireBbAttrs() {
        return requireBbAttrs;
    }

    public Set<String> allowedKeyAlgorithms() {
        return allowedKeyAlgorithms;
    }

    public boolean enforcePolicyOids() {
        return enforcePolicyOids;
    }

    public boolean requireNonRepudiation() {
        return requireNonRepudiation;
    }

    public Duration ocspMaxAge() {
        return ocspMaxAge;
    }
}
