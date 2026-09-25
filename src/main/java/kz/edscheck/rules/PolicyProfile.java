package kz.edscheck.rules;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;

public final class PolicyProfile {
    private final boolean requireTimestamp;
    private final Set<String> allowedKeyAlgorithms;
    private final boolean enforcePolicyOids;
    private final boolean requireNonRepudiation;

    private final Duration ocspMaxAge;

    private final boolean requireBbAttrs;

    private final NavigableMap<Instant, Duration> ocspSigningLowerBoundSchedule;

    private static final PolicyProfile DEFAULT = new PolicyProfile(
        false, Set.of(), false, true, Duration.ofMinutes(5), false, ocspSigningLowerBoundDefaults());

    private static NavigableMap<Instant, Duration> ocspSigningLowerBoundDefaults() {
        NavigableMap<Instant, Duration> schedule = new TreeMap<>();
        schedule.put(Instant.MIN, Duration.ofSeconds(300));
        schedule.put(Instant.parse("2026-09-05T19:00:00Z"), Duration.ZERO);
        return schedule;
    }

    public PolicyProfile(
            boolean requireTimestamp, Set<String> allowedKeyAlgorithms,
            boolean enforcePolicyOids, boolean requireNonRepudiation, Duration ocspMaxAge,
            boolean requireBbAttrs, Duration ocspSigningLowerBound) {
        this(requireTimestamp, allowedKeyAlgorithms, enforcePolicyOids, requireNonRepudiation, ocspMaxAge,
            requireBbAttrs, constantSchedule(ocspSigningLowerBound));
    }

    private PolicyProfile(
            boolean requireTimestamp, Set<String> allowedKeyAlgorithms,
            boolean enforcePolicyOids, boolean requireNonRepudiation, Duration ocspMaxAge,
            boolean requireBbAttrs, NavigableMap<Instant, Duration> ocspSigningLowerBoundSchedule) {
        this.requireTimestamp = requireTimestamp;
        this.allowedKeyAlgorithms = allowedKeyAlgorithms == null ? Set.of() : Set.copyOf(allowedKeyAlgorithms);
        this.enforcePolicyOids = enforcePolicyOids;
        this.requireNonRepudiation = requireNonRepudiation;
        this.ocspMaxAge = ocspMaxAge;
        this.requireBbAttrs = requireBbAttrs;
        this.ocspSigningLowerBoundSchedule =
            Collections.unmodifiableNavigableMap(new TreeMap<>(ocspSigningLowerBoundSchedule));
    }

    private static NavigableMap<Instant, Duration> constantSchedule(Duration value) {
        NavigableMap<Instant, Duration> schedule = new TreeMap<>();
        schedule.put(Instant.MIN, value);
        return schedule;
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

    public Duration ocspSigningLowerBound(Instant referenceTime) {
        Map.Entry<Instant, Duration> entry = ocspSigningLowerBoundSchedule.floorEntry(referenceTime);
        return entry == null ? null : entry.getValue();
    }
}
