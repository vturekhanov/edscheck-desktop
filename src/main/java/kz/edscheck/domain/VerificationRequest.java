package kz.edscheck.domain;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

public record VerificationRequest(
        String containerPath,
        String ca,
        Environment env,
        TrustMaterial trust,
        String libPath,
        Map<String, Object> providerOptions,
        Map<String, byte[]> externalOcsp,
        boolean ignoreTruststore,
        Instant checkTime) {

    public VerificationRequest {
        checkTime = ReferenceTime.truncate(Objects.requireNonNull(checkTime, "checkTime"));
        if (ca == null) {
            ca = "nca";
        }
        if (env == null) {
            env = Environment.PROD;
        }
        if (trust == null) {
            trust = TrustMaterial.empty();
        }
        providerOptions = providerOptions == null ? Map.of() : Map.copyOf(providerOptions);
        externalOcsp = externalOcsp == null ? Map.of() : Map.copyOf(externalOcsp);
    }

    public VerificationRequest(String containerPath, String ca, Environment env, Instant checkTime) {
        this(containerPath, ca, env, TrustMaterial.empty(), null, Map.of(), Map.of(), false, checkTime);
    }

    public VerificationRequest(
            String containerPath, String ca, Environment env, TrustMaterial trust, Instant checkTime) {
        this(containerPath, ca, env, trust, null, Map.of(), Map.of(), false, checkTime);
    }

    public static VerificationRequest of(String containerPath, String ca, Instant checkTime) {
        return new VerificationRequest(containerPath, ca, Environment.PROD, TrustMaterial.empty(),
            null, Map.of(), Map.of(), false, checkTime);
    }
}
