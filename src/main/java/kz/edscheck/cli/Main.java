package kz.edscheck.cli;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import kz.edscheck.Version;
import kz.edscheck.app.RunResult;
import kz.edscheck.app.Runner;
import kz.edscheck.app.RunnerParams;
import kz.edscheck.ddcard.Ddcard;
import kz.edscheck.domain.Check;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.Environment;
import kz.edscheck.domain.Signature;
import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.Verdict;
import kz.edscheck.errors.OperationalException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.online.Online;
import kz.edscheck.online.OnlineException;
import kz.edscheck.output.JsonRenderer;
import kz.edscheck.output.JsonWriter;
import kz.edscheck.output.NativeDates;
import kz.edscheck.output.TextRenderer;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.Json;
import kz.edscheck.trust.KalkanJarException;
import kz.edscheck.trust.LibraryJarException;

public final class Main {

    private static String usage() {
        return Messages.resource("/kz/edscheck/msg/usage/eds-check_" + Messages.locale().getLanguage() + ".txt");
    }

    static final long MAX_MATERIALIZED_BYTES = 500L * 1024 * 1024;

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        Args parsed;
        try {
            parsed = Args.parse(args);
        } catch (ArgsException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            System.err.println();
            System.err.print(usage());
            return 2;
        }

        Messages.setLocale(Locale.of(parsed.lang));

        if (parsed.help) {
            System.out.print(usage());
            return 0;
        }
        if (parsed.version) {
            System.out.println(Messages.get(MsgKey.MAIN_VERSION_LINE, Version.VALUE));
            return 0;
        }
        if (parsed.batch != null) {
            if (parsed.container != null) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.MAIN_BATCH_WITH_POSITIONAL)));
                return 2;
            }
            return runBatch(parsed);
        }

        if (parsed.container == null) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.MAIN_CONTAINER_REQUIRED)));
            System.err.println();
            System.err.print(usage());
            return 2;
        }

        JobResult result = runContainer(parsed);
        if (result.stdout() != null) {
            System.out.println(result.stdout());
        }
        if (!result.stderr().isEmpty()) {
            System.err.println(result.stderr());
        }
        return result.exitCode();
    }

    private static JobResult runContainer(Args parsed) {
        try {
            Trace trace = parsed.verbosity > 0
                ? message -> System.err.println(Messages.get(MsgKey.MAIN_VERBOSE_PREFIX, NativeDates.localize(message)))
                : Trace.NONE;

            DocumentSource documentSource = parsed.document != null
                ? documentSource(parsed.document) : null;

            ContainerAcquisition acquired = acquireContainer(parsed, trace);
            DocumentSource containerSource = acquired.source();
            String containerPath = acquired.containerPath();
            Map<Integer, Online.AugmentedSigner> onlineAugmented = acquired.onlineAugmented();

            if (parsed.integrityTestCombined) {
                throw new OperationalException(
                    Messages.get(MsgKey.MAIN_INTEGRITY_TEST_COMBINED_UNSUPPORTED));
            }

            Environment env = Environment.valueOf(parsed.env.toUpperCase(java.util.Locale.ROOT));
            String documentName = parsed.document != null
                ? Paths.get(parsed.document).getFileName().toString() : null;
            RunnerParams runnerParams = new RunnerParams(
                containerSource, documentSource, documentName, containerPath,
                parsed.ca, parsed.engine, env, parsed.roots, parsed.crls,
                parsed.ignoreTruststore, parsed.lib, trace);
            RunResult run = Runner.run(runnerParams);
            SignedContainer container = onlineAugmented.isEmpty()
                ? run.container() : annotateOnline(run.container(), onlineAugmented);

            String rendered = "json".equals(parsed.format)
                ? JsonRenderer.render(container, run.request())
                : TextRenderer.render(container, run.request());

            boolean anyInvalid = container.signatures().stream()
                .anyMatch(s -> s.verdict() == Verdict.INVALID);
            return new JobResult(anyInvalid ? 1 : 0, rendered, "");
        } catch (KalkanJarException | LibraryJarException e) {
            return new JobResult(2, null, Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
        } catch (OperationalException | OnlineException e) {
            return new JobResult(2, null, Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
        }
    }

    static SignedContainer annotateOnline(
            SignedContainer container, Map<Integer, Online.AugmentedSigner> augmented) {
        List<Signature> signatures = new ArrayList<>();
        for (Signature sig : container.signatures()) {
            Online.AugmentedSigner a = augmented.get(sig.index());
            if (a == null) {
                signatures.add(sig);
                continue;
            }
            List<Check> checks = new ArrayList<>();
            for (Check check : sig.checks()) {
                boolean mark = (a.tsaAdded() && check.stage() == Stage.TIMESTAMP)
                    || (a.ocspAdded() && check.stage() == Stage.REVOCATION);
                checks.add(mark ? check.withOnline(true) : check);
            }
            signatures.add(new Signature(
                sig.index(), sig.verdict(), sig.signer(), sig.referenceTime(), checks, sig.warnings(),
                sig.authority()));
        }
        return new SignedContainer(
            container.sourcePath(), container.encoding(), container.signaturesTotal(),
            signatures, container.containerFormat(), container.documentName(), container.authority());
    }

    private static int runBatch(Args template) {
        Object manifestRaw;
        try {
            String text = Files.readString(Paths.get(template.batch));
            manifestRaw = Json.parse(text);
        } catch (IOException | RuntimeException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR,
                Messages.get(MsgKey.MAIN_BATCH_MANIFEST_READ_FAILED, e.getMessage())));
            return 2;
        }
        if (!(manifestRaw instanceof List)) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.MAIN_BATCH_MANIFEST_NOT_ARRAY)));
            return 2;
        }

        List<Object> out = new ArrayList<>();
        for (Object jobObj : (List<?>) manifestRaw) {
            if (!(jobObj instanceof Map)) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR,
                    Messages.get(MsgKey.MAIN_BATCH_ENTRY_NOT_OBJECT)));
                return 2;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> job = (Map<String, Object>) jobObj;
            Object containerObj = job.get("container");
            if (!(containerObj instanceof String)) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR,
                    Messages.get(MsgKey.MAIN_BATCH_ENTRY_NO_CONTAINER)));
                return 2;
            }
            String container = (String) containerObj;
            List<String> crls = new ArrayList<>();
            Object crlRaw = job.get("crl");
            if (crlRaw instanceof List) {
                for (Object c : (List<?>) crlRaw) {
                    crls.add(String.valueOf(c));
                }
            }

            Args jobArgs = template.forBatchJob(container, crls);
            JobResult result = runContainer(jobArgs);

            Map<String, Object> record = new LinkedHashMap<>();
            record.put("container", container);
            record.put("exit_code", result.exitCode());
            record.put("stdout", result.stdout());
            record.put("stderr", result.stderr());
            out.add(record);
        }

        System.out.println(JsonWriter.write(out));
        return 0;
    }

    private record JobResult(int exitCode, String stdout, String stderr) {
    }

    private record ContainerAcquisition(
            DocumentSource source, String containerPath,
            Map<Integer, Online.AugmentedSigner> onlineAugmented) {
    }

    private static ContainerAcquisition acquireContainer(Args parsed, Trace trace) {
        try {
            String containerPath = parsed.container;
            if ("-".equals(parsed.container)) {
                return withOnlineAugmentation(parsed, readContainer(parsed.container), containerPath, trace);
            }
            Path p = Paths.get(parsed.container);
            boolean ddcard = looksLikeDdcardPdf(p);
            if (!ddcard && !parsed.online) {
                return new ContainerAcquisition(DocumentSource.ofFile(p), containerPath, Map.of());
            }
            if (!ddcard) {

                long size = Files.size(p);
                if (size > MAX_MATERIALIZED_BYTES) {
                    throw new OperationalException(Messages.get(MsgKey.MAIN_ONLINE_REQUIRES_FULL_BYTES,
                        parsed.container, size / (1024 * 1024), MAX_MATERIALIZED_BYTES / (1024 * 1024)));
                }
            }
            return withOnlineAugmentation(parsed, readContainer(parsed.container), containerPath, trace);
        } catch (IOException e) {
            throw new OperationalException(Messages.get(MsgKey.CLI_FILE_READ_FAILED, e.getMessage()), e);
        }
    }

    private static ContainerAcquisition withOnlineAugmentation(
            Args parsed, byte[] bytes, String containerPath, Trace trace) {
        if (parsed.online && "cms".equals(Ddcard.detectInputFormat(bytes))) {
            Online.AugmentResult augmented = Online.maybeAugment(
                bytes, !parsed.crls.isEmpty(), Duration.ofSeconds(10), trace);
            return new ContainerAcquisition(
                DocumentSource.ofBytes(augmented.bytes()), containerPath, augmented.augmented());
        }
        return new ContainerAcquisition(DocumentSource.ofBytes(bytes), containerPath, Map.of());
    }

    private static byte[] readContainer(String path) {
        try {
            if ("-".equals(path)) {
                try (InputStream in = System.in) {
                    return in.readAllBytes();
                }
            }
            Path p = Paths.get(path);

            if (looksLikeDdcardPdf(p)) {
                long size = Files.size(p);
                if (size > MAX_MATERIALIZED_BYTES) {
                    throw new OperationalException(Messages.get(MsgKey.MAIN_DDCARD_TOO_LARGE,
                        MAX_MATERIALIZED_BYTES / (1024 * 1024), path, size / (1024 * 1024)));
                }
            }
            return Files.readAllBytes(p);
        } catch (IOException e) {
            throw new OperationalException(Messages.get(MsgKey.CLI_FILE_READ_FAILED, e.getMessage()), e);
        }
    }

    private static boolean looksLikeDdcardPdf(Path path) throws IOException {
        byte[] prefix = new byte[5];
        try (InputStream in = Files.newInputStream(path)) {
            int n = in.readNBytes(prefix, 0, prefix.length);
            return n == prefix.length && "ddcard".equals(Ddcard.detectInputFormat(prefix));
        }
    }

    private static DocumentSource documentSource(String path) {
        return "-".equals(path) ? DocumentSource.ofStdin() : DocumentSource.ofFile(Paths.get(path));
    }

    private static final class ArgsException extends RuntimeException {
        ArgsException(String message) {
            super(message);
        }
    }

    private static final class Args {
        boolean help;
        boolean version;
        String ca = "auto";
        String env = "prod";
        List<String> roots = new ArrayList<>();
        List<String> crls = new ArrayList<>();
        boolean ignoreTruststore;
        String engine = "kalkan-java";
        String lib;
        String format = "text";
        int verbosity;
        boolean online;
        boolean integrityTestCombined;
        String document;
        String container;
        String batch;
        String lang = Messages.DEFAULT_LOCALE.getLanguage();

        Args forBatchJob(String jobContainer, List<String> jobCrls) {
            Args a = new Args();
            a.ca = this.ca;
            a.env = this.env;
            a.roots = this.roots;
            a.crls = jobCrls;
            a.ignoreTruststore = this.ignoreTruststore;
            a.engine = this.engine;
            a.lib = this.lib;
            a.format = "json";
            a.container = jobContainer;
            return a;
        }

        static Args parse(String[] args) {
            Args a = new Args();
            int i = 0;
            while (i < args.length) {
                String tok = args[i];
                if ("-h".equals(tok) || "--help".equals(tok)) {
                    a.help = true;
                    i++;
                } else if ("--version".equals(tok)) {
                    a.version = true;
                    i++;
                } else if ("--ca".equals(tok)) {
                    a.ca = value(args, i, tok);
                    i += 2;
                } else if ("--env".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!v.equals("test") && !v.equals("prod")) {
                        throw new ArgsException(Messages.get(MsgKey.MAIN_INVALID_ENV, v));
                    }
                    a.env = v;
                    i += 2;
                } else if ("--root".equals(tok)) {
                    a.roots.add(value(args, i, tok));
                    i += 2;
                } else if ("--crl".equals(tok)) {
                    a.crls.add(value(args, i, tok));
                    i += 2;
                } else if ("--ignore-truststore".equals(tok)) {
                    a.ignoreTruststore = true;
                    i++;
                } else if ("--engine".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!v.equals("kalkan-c") && !v.equals("kalkan-java")) {
                        throw new ArgsException(Messages.get(MsgKey.MAIN_INVALID_ENGINE, v));
                    }
                    a.engine = v;
                    i += 2;
                } else if ("--lib".equals(tok)) {
                    a.lib = value(args, i, tok);
                    i += 2;
                } else if ("--format".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!v.equals("text") && !v.equals("json")) {
                        throw new ArgsException(Messages.get(MsgKey.MAIN_INVALID_FORMAT, v));
                    }
                    a.format = v;
                    i += 2;
                } else if ("-v".equals(tok) || "--verbose".equals(tok)) {
                    a.verbosity++;
                    i++;
                } else if ("--online".equals(tok)) {
                    a.online = true;
                    i++;
                } else if ("--integrity-test-combined".equals(tok)) {
                    a.integrityTestCombined = true;
                    i++;
                } else if ("--document".equals(tok)) {
                    a.document = value(args, i, tok);
                    i += 2;
                } else if ("--batch".equals(tok)) {
                    a.batch = value(args, i, tok);
                    i += 2;
                } else if ("--lang".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!Messages.SUPPORTED_LOCALES.contains(v)) {
                        throw new ArgsException(Messages.get(MsgKey.CLI_INVALID_LANG,
                            v, String.join("|", Messages.SUPPORTED_LOCALES)));
                    }
                    a.lang = v;
                    i += 2;
                } else if (!"-".equals(tok) && tok.startsWith("-")) {
                    throw new ArgsException(Messages.get(MsgKey.CLI_UNKNOWN_FLAG, tok));
                } else {
                    if (a.container != null) {
                        throw new ArgsException(Messages.get(MsgKey.CLI_EXTRA_POSITIONAL_ARG, tok));
                    }
                    a.container = tok;
                    i++;
                }
            }
            return a;
        }

        private static String value(String[] args, int i, String flag) {
            if (i + 1 >= args.length) {
                throw new ArgsException(Messages.get(MsgKey.CLI_FLAG_REQUIRES_VALUE, flag));
            }
            return args[i + 1];
        }
    }
}
