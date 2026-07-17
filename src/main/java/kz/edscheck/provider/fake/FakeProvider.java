package kz.edscheck.provider.fake;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.parsing.ParsedContainer;
import kz.edscheck.parsing.ParsedSigner;
import kz.edscheck.parsing.Parsing;
import kz.edscheck.provider.CommonSigners;
import kz.edscheck.provider.ProviderResult;
import kz.edscheck.provider.SignerVerification;
import kz.edscheck.provider.StageOutcome;
import kz.edscheck.provider.TimestampInfo;
import kz.edscheck.provider.VerificationProvider;
import kz.edscheck.trust.ManifestTrust;


public final class FakeProvider implements VerificationProvider {
    private static final Set<Stage> CAPABILITIES = Set.of(
        Stage.INTEGRITY, Stage.TIMESTAMP, Stage.CHAIN, Stage.REVOCATION, Stage.ARCHIVE_TIMESTAMP);

    private final Map<Integer, FakeScenario> scenarios;
    private final FakeScenario defaultScenario;

    public FakeProvider() {
        this(Map.of(), null);
    }

    public FakeProvider(FakeScenario defaultScenario) {
        this(Map.of(), defaultScenario);
    }

    public FakeProvider(Map<Integer, FakeScenario> scenarios) {
        this(scenarios, null);
    }

    public FakeProvider(Map<Integer, FakeScenario> scenarios, FakeScenario defaultScenario) {
        this.scenarios = scenarios == null ? Map.of() : Map.copyOf(scenarios);
        this.defaultScenario = defaultScenario != null ? defaultScenario : FakeScenario.defaults();
    }

    @Override
    public String name() {
        return "fake";
    }

    @Override
    public Set<Stage> capabilities() {
        return CAPABILITIES;
    }

    @Override
    public ProviderResult verify(VerificationRequest request, byte[] container) {
        List<X509Certificate> trustCerts = ManifestTrust.loadCertificates(request.trust().roots());
        ParsedContainer parsed = Parsing.parseContainer(container, trustCerts);
        List<SignerVerification> signers = new ArrayList<>();
        for (ParsedSigner ps : parsed.signers()) {
            signers.add(ps.isForeign() ? CommonSigners.foreignSigner(ps) : signer(ps));
        }
        return new ProviderResult(parsed.encoding(), signers);
    }

    private SignerVerification signer(ParsedSigner ps) {
        FakeScenario scenario = scenarios.getOrDefault(ps.index(), defaultScenario);
        Map<Stage, StageOutcome> outcomes = new EnumMap<>(Stage.class);
        outcomes.put(Stage.INTEGRITY, new StageOutcome(scenario.integrity));
        outcomes.put(Stage.CHAIN, new StageOutcome(scenario.chain));
        outcomes.put(Stage.REVOCATION, StageOutcome.of(scenario.revocation)
            .detail(scenario.revocationDetail)
            .source(scenario.revocationSource)
            .crlUrl(scenario.revocationCrlUrl)
            .validFrom(scenario.revocationValidFrom)
            .validUntil(scenario.revocationValidUntil)
            .build());
        
        
        if (ps.archive().count() > 0) {
            CheckStatus status = scenario.archiveStatus != null ? scenario.archiveStatus : CheckStatus.PASS;
            outcomes.put(Stage.ARCHIVE_TIMESTAMP, new StageOutcome(status, scenario.archiveDetail));
        }
        return new SignerVerification(
            ps.index(), ps.certificate(), ps.keyUsage(), timestamp(ps, scenario),
            ps.archive(), outcomes, ps.chain(), List.of(), ps.missingBbAttrs());
    }

    private TimestampInfo timestamp(ParsedSigner ps, FakeScenario scenario) {
        boolean present = scenario.timestampPresent != null ? scenario.timestampPresent : ps.hasTimestamp();
        if (!present) {
            return TimestampInfo.absent();
        }
        boolean valid = scenario.timestampValid == null || scenario.timestampValid;
        Instant genTime = ps.tstGenTime() != null ? ps.tstGenTime() : ps.signingTime();
        Boolean tsaEku = scenario.tsaKeyUsageOk != null ? scenario.tsaKeyUsageOk : ps.tsaTimestampingEkuOk();
        
        
        return new TimestampInfo(true, valid, genTime, scenario.timestampDetail, tsaEku, null);
    }
}
