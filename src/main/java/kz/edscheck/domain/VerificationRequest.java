package kz.edscheck.domain;

import java.util.Map;


public record VerificationRequest(
        String containerPath,
        String ca,
        Environment env,
        TrustMaterial trust,
        String libPath,
        Map<String, Object> providerOptions,
        boolean ignoreTruststore) {

    public VerificationRequest {
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
    }

    public VerificationRequest(String containerPath, String ca, Environment env) {
        this(containerPath, ca, env, TrustMaterial.empty(), null, Map.of(), false);
    }

    public VerificationRequest(String containerPath, String ca, Environment env, TrustMaterial trust) {
        this(containerPath, ca, env, trust, null, Map.of(), false);
    }

    public static VerificationRequest of(String containerPath, String ca) {
        return new VerificationRequest(containerPath, ca, Environment.PROD, TrustMaterial.empty(),
            null, Map.of(), false);
    }
}
