package kz.edscheck.domain;

import java.util.List;


public record Signature(
        int index,
        Verdict verdict,
        Certificate signer,
        ReferenceTime referenceTime,
        List<Check> checks,
        List<String> warnings,
        String authority) {

    public Signature {
        checks = checks == null ? List.of() : List.copyOf(checks);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }

    
    public Signature(
            int index, Verdict verdict, Certificate signer, ReferenceTime referenceTime,
            List<Check> checks, List<String> warnings) {
        this(index, verdict, signer, referenceTime, checks, warnings, null);
    }
}
