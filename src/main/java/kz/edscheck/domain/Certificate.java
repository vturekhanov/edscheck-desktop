package kz.edscheck.domain;

import java.time.Instant;
import java.util.List;


public final class Certificate {
    private final String commonName;
    private final String iin;
    private final String bin;
    private final String organization;
    private final String serialNumber;
    private final String issuer;
    private final KeyAlgorithm keyAlgorithm;
    private final List<String> policyOids;
    private final List<String> subjectRoles;
    private final Instant notBefore;
    private final Instant notAfter;

    public Certificate(
            String commonName, String iin, String bin, String organization,
            String serialNumber, String issuer, KeyAlgorithm keyAlgorithm,
            List<String> policyOids, List<String> subjectRoles,
            Instant notBefore, Instant notAfter) {
        this.commonName = commonName;
        this.iin = iin;
        this.bin = bin;
        this.organization = organization;
        this.serialNumber = serialNumber;
        this.issuer = issuer;
        this.keyAlgorithm = keyAlgorithm;
        this.policyOids = policyOids == null ? List.of() : List.copyOf(policyOids);
        this.subjectRoles = subjectRoles == null ? List.of() : List.copyOf(subjectRoles);
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    
    public static Certificate empty() {
        return new Certificate(null, null, null, null, null, null, null,
            List.of(), List.of(), null, null);
    }

    
    public static Certificate withValidity(Instant notBefore, Instant notAfter) {
        return new Certificate(null, null, null, null, null, null, null,
            List.of(), List.of(), notBefore, notAfter);
    }

    public String commonName() {
        return commonName;
    }

    public String iin() {
        return iin;
    }

    public String bin() {
        return bin;
    }

    public String organization() {
        return organization;
    }

    public String serialNumber() {
        return serialNumber;
    }

    public String issuer() {
        return issuer;
    }

    public KeyAlgorithm keyAlgorithm() {
        return keyAlgorithm;
    }

    public List<String> policyOids() {
        return policyOids;
    }

    public List<String> subjectRoles() {
        return subjectRoles;
    }

    public Instant notBefore() {
        return notBefore;
    }

    public Instant notAfter() {
        return notAfter;
    }

    
    public static final class Builder {
        private String commonName;
        private String iin;
        private String bin;
        private String organization;
        private String serialNumber;
        private String issuer;
        private KeyAlgorithm keyAlgorithm;
        private List<String> policyOids = List.of();
        private List<String> subjectRoles = List.of();
        private Instant notBefore;
        private Instant notAfter;

        public Builder commonName(String v) {
            this.commonName = v;
            return this;
        }

        public Builder iin(String v) {
            this.iin = v;
            return this;
        }

        public Builder bin(String v) {
            this.bin = v;
            return this;
        }

        public Builder organization(String v) {
            this.organization = v;
            return this;
        }

        public Builder serialNumber(String v) {
            this.serialNumber = v;
            return this;
        }

        public Builder issuer(String v) {
            this.issuer = v;
            return this;
        }

        public Builder keyAlgorithm(KeyAlgorithm v) {
            this.keyAlgorithm = v;
            return this;
        }

        public Builder policyOids(List<String> v) {
            this.policyOids = v;
            return this;
        }

        public Builder subjectRoles(List<String> v) {
            this.subjectRoles = v;
            return this;
        }

        public Builder notBefore(Instant v) {
            this.notBefore = v;
            return this;
        }

        public Builder notAfter(Instant v) {
            this.notAfter = v;
            return this;
        }

        public Certificate build() {
            return new Certificate(commonName, iin, bin, organization, serialNumber,
                issuer, keyAlgorithm, policyOids, subjectRoles, notBefore, notAfter);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
