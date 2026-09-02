package kz.edscheck.app;

import java.util.List;
import java.util.Map;

import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.Environment;
import kz.edscheck.trace.Trace;

public record RunnerParams(
        DocumentSource containerSource,
        DocumentSource documentSource,
        String documentName,
        String containerPathHint,
        String ca,
        String engine,
        Environment env,
        List<String> roots,
        List<String> crls,
        boolean ignoreTruststore,
        String lib,
        Trace trace,
        Map<String, byte[]> externalOcsp) {

    public RunnerParams {
        roots = roots == null ? List.of() : List.copyOf(roots);
        crls = crls == null ? List.of() : List.copyOf(crls);
        trace = trace == null ? Trace.NONE : trace;
        externalOcsp = externalOcsp == null ? Map.of() : Map.copyOf(externalOcsp);
    }

    public RunnerParams(
            DocumentSource containerSource, DocumentSource documentSource, String documentName,
            String containerPathHint, String ca, String engine, Environment env,
            List<String> roots, List<String> crls, boolean ignoreTruststore, String lib, Trace trace) {
        this(containerSource, documentSource, documentName, containerPathHint, ca, engine, env,
            roots, crls, ignoreTruststore, lib, trace, Map.of());
    }
}
