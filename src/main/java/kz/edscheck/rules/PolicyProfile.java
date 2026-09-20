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

    private final Duration ocspSigningLowerBound;

    private static final PolicyProfile DEFAULT = new PolicyProfile(
        false, Set.of(), false, true, Duration.ofMinutes(5), false, Duration.ofSeconds(300));

    public PolicyProfile(
            boolean requireTimestamp, Set<String> allowedKeyAlgorithms,
            boolean enforcePolicyOids, boolean requireNonRepudiation, Duration ocspMaxAge,
            boolean requireBbAttrs, Duration ocspSigningLowerBound) {
        this.requireTimestamp = requireTimestamp;
        this.allowedKeyAlgorithms = allowedKeyAlgorithms == null ? Set.of() : Set.copyOf(allowedKeyAlgorithms);
        this.enforcePolicyOids = enforcePolicyOids;
        this.requireNonRepudiation = requireNonRepudiation;
        this.ocspMaxAge = ocspMaxAge;
        this.requireBbAttrs = requireBbAttrs;
        this.ocspSigningLowerBound = ocspSigningLowerBound;
    }

    public static PolicyProfile ncaPolicy() {
        return DEFAULT;
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

    public Duration ocspSigningLowerBound() {
        return ocspSigningLowerBound;
    }
}
