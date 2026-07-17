package kz.edscheck.app;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import kz.edscheck.ddcard.Ddcard;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.TrustMaterial;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.engine.VerificationEngine;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.errors.OperationalException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.provider.VerificationProvider;
import kz.edscheck.provider.fake.FakeProvider;
import kz.edscheck.provider.kalkan.KalkanProvider;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.KalkanJar;
import kz.edscheck.trust.KalkanJarException;
import kz.edscheck.trust.LibraryJarException;
import kz.edscheck.trust.LibraryJars;
import kz.edscheck.trust.ManifestTrust;


public final class Runner {
    private Runner() {
    }

    public static RunResult run(RunnerParams params) throws KalkanJarException, LibraryJarException {
        
        
        
        
        
        if (params.documentSource() == null && looksLikeDdcard(params.containerSource())) {
            LibraryJars.verifyRuntime(LibraryJars.resolveDirFromSystemProperty());
        }

        List<String> roots = params.roots().isEmpty()
            ? ManifestTrust.trustedCerts(params.ca(), params.env().jsonValue())
            : params.roots();
        TrustMaterial trust = new TrustMaterial(roots, params.crls());
        VerificationRequest request = new VerificationRequest(
            params.containerPathHint(), params.ca(), params.env(), trust, params.lib(),
            Map.of(), params.ignoreTruststore());

        VerificationProvider provider = buildProvider(params.ca(), params.engine(), params.trace());
        VerificationEngine engine = new VerificationEngine(provider);

        SignedContainer result;
        if (params.documentSource() != null) {
            
            
            byte[] signatureBytes = readAllBytes(params.containerSource());
            result = engine.verifyDetached(
                request, params.documentSource(), List.of(signatureBytes), params.documentName());
        } else {
            result = engine.verify(request, params.containerSource());
        }
        return new RunResult(result, request);
    }

    private static boolean looksLikeDdcard(DocumentSource containerSource) {
        try {
            return Ddcard.looksLikeDdcard(containerSource);
        } catch (IOException e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
        }
    }

    private static byte[] readAllBytes(DocumentSource source) {
        try {
            return source.readAllBytes();
        } catch (IOException e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
        }
    }

    private static VerificationProvider buildProvider(String ca, String engine, Trace trace)
            throws KalkanJarException {
        if ("fake".equals(ca)) {
            
            return new FakeProvider();
        }
        if (ca.equals("nca") || ca.equals("btsd") || ca.equals("ucgo") || ca.equals("auto")) {
            if ("kalkan-c".equals(engine)) {
                throw new OperationalException(Messages.get(MsgKey.RUNNER_KALKAN_C_UNAVAILABLE));
            }
            
            
            KalkanJar.resolveAndVerify();
            return new KalkanProvider(trace);
        }
        throw new OperationalException(Messages.get(MsgKey.RUNNER_UNKNOWN_CA_PROVIDER, ca));
    }
}
