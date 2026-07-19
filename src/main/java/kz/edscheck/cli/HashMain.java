package kz.edscheck.cli;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.trust.Digests;
import kz.edscheck.trust.KalkanJar;
import kz.edscheck.trust.KalkanJarException;
import kz.edscheck.trust.KalkanProviderRegistrar;

public final class HashMain {
    private record Algo(String jceName, String label, String oid) {
    }

    private static final Map<String, Algo> ALGOS = new LinkedHashMap<>();

    static {
        ALGOS.put("gost2015", new Algo(
            "GOST3411-2015-512", Messages.get(MsgKey.HASH_ALGO_LABEL_GOST2015_512), "1.2.398.3.10.1.3.3"));
        ALGOS.put("gost2015-256", new Algo(
            "GOST3411-2015-256", Messages.get(MsgKey.HASH_ALGO_LABEL_GOST2015_256), "1.2.398.3.10.1.3.2"));
        ALGOS.put("gost95", new Algo("GOST3411", Messages.get(MsgKey.HASH_ALGO_LABEL_GOST95), null));
        ALGOS.put("gost94", new Algo("GOSTR341194", Messages.get(MsgKey.HASH_ALGO_LABEL_GOST94), null));
        ALGOS.put("sha256", new Algo(
            "SHA-256", "SHA-256", "2.16.840.1.101.3.4.2.1"));
    }

    private static final String DEFAULT_ALGO = "gost2015";

    private static String usage() {
        return Messages.resource("/kz/edscheck/msg/usage/hash_" + Messages.locale().getLanguage() + ".txt")
            .replace("{{algo_list}}", String.join("|", ALGOS.keySet()))
            .replace("{{default_algo}}", DEFAULT_ALGO);
    }

    private HashMain() {
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        List<String> paths = new ArrayList<>();
        String algoName = DEFAULT_ALGO;
        boolean quiet = false;
        boolean help = false;
        String lang = Messages.DEFAULT_LOCALE.getLanguage();

        int i = 0;
        while (i < args.length) {
            String tok = args[i];
            if ("-h".equals(tok) || "--help".equals(tok)) {
                help = true;
                i++;
            } else if ("-a".equals(tok) || "--algo".equals(tok)) {
                if (i + 1 >= args.length) {
                    System.err.println(Messages.get(MsgKey.CLI_ERROR,
                        Messages.get(MsgKey.CLI_FLAG_REQUIRES_VALUE, tok)));
                    return 2;
                }
                algoName = args[i + 1];
                i += 2;
            } else if ("-q".equals(tok) || "--quiet".equals(tok)) {
                quiet = true;
                i++;
            } else if ("--lang".equals(tok)) {
                if (i + 1 >= args.length) {
                    System.err.println(Messages.get(MsgKey.CLI_ERROR,
                        Messages.get(MsgKey.CLI_FLAG_REQUIRES_VALUE, tok)));
                    return 2;
                }
                lang = args[i + 1];
                if (!Messages.SUPPORTED_LOCALES.contains(lang)) {
                    System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.CLI_INVALID_LANG,
                        lang, String.join("|", Messages.SUPPORTED_LOCALES))));
                    return 2;
                }
                i += 2;
            } else if (!"-".equals(tok) && tok.startsWith("-")) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.CLI_UNKNOWN_FLAG, tok)));
                return 2;
            } else {
                paths.add(tok);
                i++;
            }
        }

        Messages.setLocale(Locale.of(lang));

        if (help) {
            System.out.print(usage());
            return 0;
        }

        if (paths.isEmpty()) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.HASH_FILE_REQUIRED)));
            System.err.println();
            System.err.print(usage());
            return 2;
        }
        Algo algo = ALGOS.get(algoName);
        if (algo == null) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR,
                Messages.get(MsgKey.HASH_INVALID_ALGO, algoName, String.join("|", ALGOS.keySet()))));
            return 2;
        }

        String libLabel;
        MessageDigest md;
        try {
            libLabel = Messages.get(MsgKey.HASH_LIB_LABEL, KalkanJar.resolveAndVerify());
            KalkanProviderRegistrar.ensureSecurityProviderRegistered();
            md = MessageDigest.getInstance(algo.jceName(), "KALKAN");
        } catch (KalkanJarException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR,
                Messages.get(MsgKey.HASH_ALGO_UNSUPPORTED, algo.jceName(), e.getMessage())));
            return 2;
        }

        boolean anyError = false;
        List<String> blocks = new ArrayList<>();
        for (String cliName : paths) {
            String displayName = "-".equals(cliName) ? "stdin" : cliName;
            md.reset();
            long size;
            byte[] digest;
            try {
                if ("-".equals(cliName)) {

                    size = Digests.update(System.in, md);
                } else {
                    try (InputStream in = Files.newInputStream(Paths.get(cliName))) {
                        size = Digests.update(in, md);
                    }
                }
                digest = md.digest();
            } catch (IOException e) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR,
                    Messages.get(MsgKey.HASH_FILE_READ_FAILED, cliName, e.getMessage())));
                anyError = true;
                continue;
            }

            if (quiet) {

                System.out.println(hex(digest) + "  " + cliName);
            } else {
                blocks.add(render(displayName, size, algo, libLabel, digest));
            }
        }
        if (!blocks.isEmpty()) {
            System.out.println(String.join("\n\n", blocks));
        }
        return anyError ? 2 : 0;
    }

    private static String render(String displayName, long size, Algo algo, String libLabel, byte[] digest) {
        List<String> lines = new ArrayList<>();
        lines.add(Messages.get(MsgKey.HASH_LINE_FILE, displayName, size));
        lines.add(Messages.get(MsgKey.HASH_LINE_ALGORITHM, algo.label(), digest.length * 8));
        if (algo.oid() != null) {
            lines.add(Messages.get(MsgKey.HASH_LINE_OID, algo.oid()));
        }
        lines.add(Messages.get(MsgKey.HASH_LINE_LIBRARY, libLabel));
        lines.add(Messages.get(MsgKey.HASH_LINE_HASH_HEX, hex(digest)));
        lines.add(Messages.get(MsgKey.HASH_LINE_HASH_BASE64, Base64.getEncoder().encodeToString(digest)));
        return String.join("\n", lines);
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
