package kz.edscheck.cli;

import java.io.Console;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.ParsedContainer;
import kz.edscheck.parsing.ParsedSigner;
import kz.edscheck.parsing.Parsing;
import kz.edscheck.sign.cades.ArchiveTimestamp;
import kz.edscheck.sign.cades.AttrOps;
import kz.edscheck.sign.cades.CadesBltBuilder;
import kz.edscheck.sign.cades.CadesSigner;
import kz.edscheck.sign.cades.CertificatesOps;
import kz.edscheck.sign.cades.ChainResolver;
import kz.edscheck.sign.cades.CoSign;
import kz.edscheck.sign.cades.SignException;
import kz.edscheck.sign.cades.SignerSelector;
import kz.edscheck.sign.cades.SortSignerInfos;
import kz.edscheck.sign.cades.StrictBlt;
import kz.edscheck.sign.cades.StripSignature;
import kz.edscheck.trust.KalkanJar;
import kz.edscheck.trust.KalkanJarException;


public final class SignMain {
    private static final Path KEYS_VALID_DIR = Paths.get(".keys", "valid");

    
    private static String usage() {
        return Messages.resource("/kz/edscheck/msg/usage/sign_" + Messages.locale().getLanguage() + ".txt");
    }

    private SignMain() {
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
        boolean multipleOps = countTrue(parsed.addTarget != null, parsed.stripTarget != null,
            parsed.sortSignerInfos != null) > 1;
        if (multipleOps) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.SIGN_MULTIPLE_OPS)));
            return 2;
        }
        if (parsed.force && !isForceable(parsed.addTarget)) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.SIGN_FORCE_NOT_APPLICABLE)));
            return 2;
        }
        boolean indexApplicable = parsed.addTarget != null || parsed.stripTarget != null
            || parsed.addChain != null || parsed.archive != null;
        if (parsed.index != null && !indexApplicable) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.SIGN_INDEX_NOT_APPLICABLE)));
            return 2;
        }
        if ("signature".equals(parsed.stripTarget) && (parsed.index == null || "all".equals(parsed.index))) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR,
                Messages.get(MsgKey.SIGN_STRIP_SIGNATURE_REQUIRES_INDEX)));
            return 2;
        }
        if (parsed.sortSignerInfos != null) {
            if (parsed.inputFile == null) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.SIGN_SORT_REQUIRES_FILE)));
                return 2;
            }
            return runSortSignerInfos(parsed);
        }
        if (parsed.addChain != null) {
            if (parsed.inputFile != null) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR,
                    Messages.get(MsgKey.SIGN_ADD_CHAIN_WITH_POSITIONAL)));
                return 2;
            }
            return runAddChain(Paths.get(parsed.addChain), parsed.out, selectorFromArgs(parsed));
        }
        if (parsed.archive != null) {
            if (parsed.inputFile != null) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR,
                    Messages.get(MsgKey.SIGN_ARCHIVE_WITH_POSITIONAL)));
                return 2;
            }
            return runArchive(Paths.get(parsed.archive), parsed.out, selectorFromArgs(parsed));
        }
        if (parsed.addTarget != null) {
            if (parsed.inputFile == null) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR,
                    Messages.get(MsgKey.SIGN_ADD_REQUIRES_FILE, parsed.addTarget)));
                return 2;
            }
            return runAdd(parsed);
        }
        if (parsed.stripTarget != null) {
            if (parsed.inputFile == null) {
                System.err.println(Messages.get(MsgKey.CLI_ERROR,
                    Messages.get(MsgKey.SIGN_STRIP_REQUIRES_FILE, parsed.stripTarget)));
                return 2;
            }
            return runStrip(parsed);
        }
        if (parsed.inputFile == null) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, Messages.get(MsgKey.SIGN_INPUT_FILE_REQUIRED)));
            System.err.println();
            System.err.print(usage());
            return 2;
        }
        return runSign(parsed);
    }

    private static boolean isForceable(String addTarget) {
        return "tsp".equals(addTarget) || "ocsp".equals(addTarget) || "tsp-ocsp".equals(addTarget);
    }

    private static int countTrue(boolean... flags) {
        int n = 0;
        for (boolean f : flags) {
            if (f) {
                n++;
            }
        }
        return n;
    }

    private static SignerSelector selectorFromArgs(Args parsed) {
        if (parsed.index == null) {
            return SignerSelector.single();
        }
        if ("all".equals(parsed.index)) {
            return SignerSelector.all();
        }
        return SignerSelector.at(Integer.parseInt(parsed.index));
    }

    
    private static int runSign(Args parsed) {
        char[] password = null;
        try {
            KalkanJar.resolveAndVerify();
            KalkanJar.ensureSecurityProviderRegistered();

            byte[] inputBytes = Files.readAllBytes(Paths.get(parsed.inputFile));
            if (CoSign.looksLikeCades(inputBytes)) {
                return runCoSign(parsed, inputBytes);
            }
            if (parsed.document != null) {
                throw new SignException(Messages.get(MsgKey.SIGN_DOCUMENT_ONLY_FOR_COSIGN));
            }

            Path p12Path = resolveP12Path(parsed.key);
            System.out.println(Messages.get(MsgKey.SIGN_LINE_KEY, p12Path.getFileName()));
            password = readPassword();

            boolean encapsulate = "attached".equals(parsed.mode);
            System.out.println(Messages.get(MsgKey.SIGN_LINE_MODE, parsed.mode, inputBytes.length));

            System.out.println(Messages.get(MsgKey.SIGN_FETCHING_SIGNER_CERT));
            X509Certificate signerCert = CadesSigner.loadSignerCertificate(p12Path.toString(), password);
            System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_SIGNER,
                shorten(signerCert.getSubjectX500Principal().getName())));

            List<X509Certificate> chainCerts = List.of();
            if (parsed.fullchain) {
                chainCerts = ChainResolver.resolveChain(signerCert);
                if (chainCerts.isEmpty()) {
                    throw new SignException(Messages.get(MsgKey.SIGN_FULLCHAIN_ISSUER_NOT_FOUND));
                }
                System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_CHAIN_FULLCHAIN,
                    chainCerts.size(), 1 + chainCerts.size()));
                for (X509Certificate c : chainCerts) {
                    System.out.println("    " + shorten(c.getSubjectX500Principal().getName()));
                }
            }

            System.out.println(Messages.get(MsgKey.SIGN_SIGNING));
            byte[] cms = CadesSigner.sign(p12Path.toString(), password, inputBytes, encapsulate, chainCerts);
            System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_SIGNATURE_CREATED, cms.length));

            System.out.println(Messages.get(MsgKey.SIGN_AUGMENTING_FIRST));
            cms = CadesBltBuilder.augmentWithOcspAndTsa(cms);
            System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_BLT_READY, cms.length));

            if (parsed.strictBlt) {
                System.out.println(Messages.get(MsgKey.SIGN_STRICT_BLT_APPLYING));
                cms = StrictBlt.apply(cms, 0);
                System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_DONE, cms.length));
            }

            Path outPath = parsed.out != null ? Paths.get(parsed.out) : defaultOutPath();
            writeOutput(outPath, cms);
            System.out.println(Messages.get(MsgKey.SIGN_SAVED, outPath));
            if (encapsulate) {
                System.out.println(Messages.get(MsgKey.SIGN_VERIFY_HINT_ATTACHED, outPath));
            } else {
                System.out.println(Messages.get(MsgKey.SIGN_VERIFY_HINT_DETACHED, parsed.inputFile, outPath));
            }
            return 0;
        } catch (KalkanJarException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } catch (SignException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } catch (IOException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR,
                Messages.get(MsgKey.CLI_FILE_READ_WRITE_FAILED, e.getMessage())));
            return 2;
        } catch (Exception e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    
    private static int runCoSign(Args parsed, byte[] existingCmsDer) {
        char[] password = null;
        try {
            if (parsed.modeExplicit) {
                throw new SignException(Messages.get(MsgKey.SIGN_MODE_WITH_COSIGN));
            }

            byte[] document = null;
            if (!CoSign.isAttached(existingCmsDer)) {
                if (parsed.document == null) {
                    throw new SignException(Messages.get(MsgKey.SIGN_COSIGN_DETACHED_NEEDS_DOCUMENT));
                }
                document = Files.readAllBytes(Paths.get(parsed.document));
            } else if (parsed.document != null) {
                throw new SignException(Messages.get(MsgKey.SIGN_COSIGN_ATTACHED_NO_DOCUMENT));
            }

            Path p12Path = resolveP12Path(parsed.key);
            System.out.println(Messages.get(MsgKey.SIGN_LINE_KEY, p12Path.getFileName()));
            password = readPassword();

            System.out.println(Messages.get(MsgKey.SIGN_COSIGN_INTRO));
            System.out.println(Messages.get(MsgKey.SIGN_FETCHING_SIGNER_CERT));
            X509Certificate signerCert = CadesSigner.loadSignerCertificate(p12Path.toString(), password);
            System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_SIGNER,
                shorten(signerCert.getSubjectX500Principal().getName())));

            List<X509Certificate> chainCerts = List.of();
            if (parsed.fullchain) {
                chainCerts = ChainResolver.resolveChain(signerCert);
                if (chainCerts.isEmpty()) {
                    throw new SignException(Messages.get(MsgKey.SIGN_FULLCHAIN_ISSUER_NOT_FOUND));
                }
                System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_CHAIN_FULLCHAIN,
                    chainCerts.size(), 1 + chainCerts.size()));
            }

            CoSign.Result signed = CoSign.addSigner(
                existingCmsDer, document, p12Path.toString(), password, chainCerts);
            System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_NEW_SIGNER_ADDED,
                signed.newIndex(), signed.bytes().length));

            System.out.println(Messages.get(MsgKey.SIGN_AUGMENTING_COSIGN));
            byte[] cms = CadesBltBuilder.augmentWithOcspAndTsa(signed.bytes(), signed.newIndex());
            System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_BLT_READY, cms.length));

            if (parsed.strictBlt) {
                System.out.println(Messages.get(MsgKey.SIGN_STRICT_BLT_APPLYING));
                cms = StrictBlt.apply(cms, signed.newIndex());
                System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_DONE, cms.length));
            }

            Path outPath = parsed.out != null ? Paths.get(parsed.out) : defaultOutPath();
            writeOutput(outPath, cms);
            System.out.println(Messages.get(MsgKey.SIGN_SAVED, outPath));
            System.out.println(Messages.get(MsgKey.SIGN_VERIFY_HINT_ATTACHED, outPath)
                + (document != null ? " " + Messages.get(MsgKey.SIGN_VERIFY_HINT_DOCUMENT_SUFFIX, parsed.document) : ""));
            return 0;
        } catch (KalkanJarException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } catch (SignException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } catch (IOException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR,
                Messages.get(MsgKey.CLI_FILE_READ_WRITE_FAILED, e.getMessage())));
            return 2;
        } catch (Exception e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    
    private static int runAddChain(Path chainPath, String out, SignerSelector selector) {
        return runAttrOp(chainPath, out, "_fullchain", Messages.get(MsgKey.SIGN_ACTION_ADD_CHAIN) + " ",
            cmsDer -> {
            ParsedContainer parsedContainer = Parsing.parseContainer(cmsDer, List.of());
            List<Integer> indices = selector.resolve(parsedContainer.signers().size());

            List<X509Certificate> newCerts = new ArrayList<>();
            for (int idx : indices) {
                ParsedSigner ps = parsedContainer.signers().get(idx);
                X509Certificate signerCert = ps.signerCertRaw();
                if (signerCert == null) {
                    throw new SignException(Messages.get(MsgKey.SIGN_SIGNER_CERT_NOT_FOUND, idx));
                }
                List<X509Certificate> chain = ChainResolver.resolveChain(signerCert);
                if (chain.isEmpty()) {
                    throw new SignException(Messages.get(MsgKey.SIGN_CHAIN_ISSUER_NOT_FOUND, idx));
                }
                newCerts.addAll(chain);
            }
            byte[] result = CertificatesOps.appendCertificates(cmsDer, newCerts);
            boolean changed = result != cmsDer;
            String message = changed
                ? Messages.get(MsgKey.SIGN_CHAIN_ADDED, indices.size())
                : Messages.get(MsgKey.SIGN_CHAIN_ALREADY_PRESENT);
            return new AttrOps.Result(result, changed, List.of(message));
        });
    }

    
    private static int runArchive(Path archivePath, String out, SignerSelector selector) {
        return runAttrOp(archivePath, out, "_archived", Messages.get(MsgKey.SIGN_ACTION_ADD_ARCHIVE) + " ",
            cmsDer -> ArchiveTimestamp.addArchiveTimestamp(
                cmsDer, CadesBltBuilder.TSA_URL, CadesBltBuilder.TSA_REQ_POLICY,
                archivePath.toString(), selector));
    }

    
    private static int runAdd(Args parsed) {
        SignerSelector selector = selectorFromArgs(parsed);
        if ("chain".equals(parsed.addTarget)) {
            return runAddChain(Paths.get(parsed.inputFile), parsed.out, selector);
        }
        if ("archive".equals(parsed.addTarget)) {
            return runArchive(Paths.get(parsed.inputFile), parsed.out, selector);
        }
        Set<AttrOps.Attr> targets = switch (parsed.addTarget) {
            case "tsp" -> EnumSet.of(AttrOps.Attr.TSP);
            case "ocsp" -> EnumSet.of(AttrOps.Attr.OCSP);
            case "tsp-ocsp" -> EnumSet.of(AttrOps.Attr.TSP, AttrOps.Attr.OCSP);
            default -> throw new IllegalStateException(Messages.get(MsgKey.SIGN_UNREACHABLE, parsed.addTarget));
        };
        return runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_augmented",
            Messages.get(MsgKey.SIGN_ACTION_ADD_ATTR,
                parsed.addTarget + (parsed.force ? " (--force)" : "")) + " ",
            cmsDer -> AttrOps.add(cmsDer, targets, parsed.force, selector));
    }

    
    private static int runStrip(Args parsed) {
        SignerSelector selector = selectorFromArgs(parsed);
        return switch (parsed.stripTarget) {
            case "tsp" -> runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_stripped",
                Messages.get(MsgKey.SIGN_ACTION_STRIP_TSP) + " ",
                cmsDer -> AttrOps.strip(cmsDer, AttrOps.Attr.TSP, selector));
            case "ocsp" -> runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_stripped",
                Messages.get(MsgKey.SIGN_ACTION_STRIP_OCSP) + " ",
                cmsDer -> AttrOps.strip(cmsDer, AttrOps.Attr.OCSP, selector));
            case "archive" -> runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_stripped",
                Messages.get(MsgKey.SIGN_ACTION_STRIP_ARCHIVE) + " ",
                cmsDer -> ArchiveTimestamp.stripArchive(cmsDer, false, selector));
            case "archive-all" -> runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_stripped",
                Messages.get(MsgKey.SIGN_ACTION_STRIP_ARCHIVE_ALL) + " ",
                cmsDer -> ArchiveTimestamp.stripArchive(cmsDer, true, selector));
            case "unsigned" -> runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_stripped",
                Messages.get(MsgKey.SIGN_ACTION_STRIP_UNSIGNED) + " ",
                cmsDer -> AttrOps.stripUnsigned(cmsDer, selector));
            case "signature" -> runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_stripped",
                Messages.get(MsgKey.SIGN_ACTION_STRIP_SIGNATURE, parsed.index) + " ",
                cmsDer -> StripSignature.strip(cmsDer, Integer.parseInt(parsed.index)));
            default -> throw new IllegalStateException(Messages.get(MsgKey.SIGN_UNREACHABLE, parsed.stripTarget));
        };
    }

    
    private static int runSortSignerInfos(Args parsed) {
        SortSignerInfos.Criterion criterion = "der".equals(parsed.sortSignerInfos)
            ? SortSignerInfos.Criterion.DER : SortSignerInfos.Criterion.TIME;
        return runAttrOp(Paths.get(parsed.inputFile), parsed.out, "_sorted",
            Messages.get(MsgKey.SIGN_ACTION_SORT, parsed.sortSignerInfos) + " ",
            cmsDer -> SortSignerInfos.sort(cmsDer, criterion));
    }

    
    private static int runAttrOp(Path inPath, String out, String suffix, String actionLabel,
                                  Function<byte[], AttrOps.Result> op) {
        try {
            byte[] cmsDer = Files.readAllBytes(inPath);
            System.out.println(actionLabel + inPath.getFileName() + " ...");

            AttrOps.Result result = op.apply(cmsDer);
            for (String message : result.messages()) {
                System.out.println("  " + message);
            }
            if (!result.changed()) {
                System.out.println(Messages.get(MsgKey.SIGN_NO_CHANGES));
                return 0;
            }
            System.out.println("  " + Messages.get(MsgKey.SIGN_LINE_DONE, result.bytes().length));

            Path outPath = out != null ? Paths.get(out) : withSuffix(inPath, suffix);
            writeOutput(outPath, result.bytes());
            System.out.println(Messages.get(MsgKey.SIGN_SAVED, outPath));
            return 0;
        } catch (SignException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        } catch (IOException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR,
                Messages.get(MsgKey.CLI_FILE_READ_WRITE_FAILED, e.getMessage())));
            return 2;
        } catch (Exception e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            return 2;
        }
    }

    private static void writeOutput(Path outPath, byte[] data) throws IOException {
        if (outPath.getParent() != null) {
            Files.createDirectories(outPath.getParent());
        }
        Files.write(outPath, data);
    }

    
    private static Path withSuffix(Path path, String suffix) {
        String name = path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String stem = dot > 0 ? name.substring(0, dot) : name;
        String ext = dot > 0 ? name.substring(dot) : "";
        Path parent = path.getParent();
        return parent != null ? parent.resolve(stem + suffix + ext) : Paths.get(stem + suffix + ext);
    }

    private static Path resolveP12Path(String explicit) {
        if (explicit != null) {
            Path p = Paths.get(explicit);
            if (!Files.isRegularFile(p)) {
                throw new SignException(Messages.get(MsgKey.SIGN_KEY_FILE_NOT_FOUND, p));
            }
            return p;
        }
        return findValidP12();
    }

    
    private static Path findValidP12() {
        if (!Files.isDirectory(KEYS_VALID_DIR)) {
            throw new SignException(Messages.get(MsgKey.SIGN_KEYS_DIR_MISSING, KEYS_VALID_DIR));
        }
        List<Path> candidates = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(KEYS_VALID_DIR, "*.p12")) {
            stream.forEach(candidates::add);
        } catch (IOException e) {
            throw new SignException(Messages.get(MsgKey.SIGN_KEYS_DIR_READ_FAILED, KEYS_VALID_DIR, e.getMessage()));
        }
        candidates.sort(Path::compareTo);
        if (candidates.isEmpty()) {
            throw new SignException(Messages.get(MsgKey.SIGN_NO_P12_FOUND, KEYS_VALID_DIR));
        }
        if (candidates.size() > 1) {
            StringBuilder names = new StringBuilder();
            for (Path c : candidates) {
                if (names.length() > 0) {
                    names.append(", ");
                }
                names.append(c.getFileName());
            }
            throw new SignException(Messages.get(MsgKey.SIGN_MULTIPLE_P12_FOUND, KEYS_VALID_DIR, names));
        }
        return candidates.get(0);
    }

    private static char[] readPassword() {
        Console console = System.console();
        if (console == null) {
            throw new SignException(Messages.get(MsgKey.SIGN_NO_INTERACTIVE_CONSOLE));
        }
        
        
        char[] pwd = console.readPassword(Messages.get(MsgKey.SIGN_PASSWORD_PROMPT) + " ");
        if (pwd == null) {
            throw new SignException(Messages.get(MsgKey.SIGN_PASSWORD_INPUT_CANCELLED));
        }
        return pwd;
    }

    private static Path defaultOutPath() {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        return Paths.get("tmp", "cades_blt_" + ts + ".cms");
    }

    private static String shorten(String s) {
        return s.length() > 80 ? s.substring(0, 80) : s;
    }

    private static final class ArgsException extends RuntimeException {
        ArgsException(String message) {
            super(message);
        }
    }

    private static final Set<String> ADD_TARGETS = Set.of("tsp", "ocsp", "tsp-ocsp", "archive", "chain");
    private static final Set<String> STRIP_TARGETS =
        Set.of("tsp", "ocsp", "archive", "archive-all", "unsigned", "signature");
    private static final Set<String> SORT_CRITERIA = Set.of("time", "der");

    private static final class Args {
        boolean help;
        String mode = "attached";
        boolean modeExplicit;
        String out;
        String key;
        boolean fullchain;
        String addChain;
        String archive;
        boolean strictBlt;
        String inputFile;
        String addTarget;
        String stripTarget;
        boolean force;
        String index;
        String document;
        String sortSignerInfos;
        String lang = Messages.DEFAULT_LOCALE.getLanguage();

        static Args parse(String[] args) {
            Args a = new Args();
            int i = 0;
            while (i < args.length) {
                String tok = args[i];
                if ("-h".equals(tok) || "--help".equals(tok)) {
                    a.help = true;
                    i++;
                } else if ("--mode".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!v.equals("attached") && !v.equals("detached")) {
                        throw new ArgsException(Messages.get(MsgKey.SIGN_INVALID_MODE, v));
                    }
                    a.mode = v;
                    a.modeExplicit = true;
                    i += 2;
                } else if ("--out".equals(tok)) {
                    a.out = value(args, i, tok);
                    i += 2;
                } else if ("--key".equals(tok)) {
                    a.key = value(args, i, tok);
                    i += 2;
                } else if ("--document".equals(tok)) {
                    a.document = value(args, i, tok);
                    i += 2;
                } else if ("--fullchain".equals(tok)) {
                    a.fullchain = true;
                    i++;
                } else if ("--add-chain".equals(tok)) {
                    a.addChain = value(args, i, tok);
                    i += 2;
                } else if ("--archive".equals(tok)) {
                    a.archive = value(args, i, tok);
                    i += 2;
                } else if ("--strict-blt".equals(tok)) {
                    a.strictBlt = true;
                    i++;
                } else if ("--add".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!ADD_TARGETS.contains(v)) {
                        throw new ArgsException(Messages.get(MsgKey.SIGN_INVALID_ADD, v));
                    }
                    a.addTarget = v;
                    i += 2;
                } else if ("--strip".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!STRIP_TARGETS.contains(v)) {
                        throw new ArgsException(Messages.get(MsgKey.SIGN_INVALID_STRIP, v));
                    }
                    a.stripTarget = v;
                    i += 2;
                } else if ("--force".equals(tok)) {
                    a.force = true;
                    i++;
                } else if ("--index".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!"all".equals(v)) {
                        try {
                            if (Integer.parseInt(v) < 0) {
                                throw new ArgsException(Messages.get(MsgKey.SIGN_INDEX_NEGATIVE, v));
                            }
                        } catch (NumberFormatException e) {
                            throw new ArgsException(Messages.get(MsgKey.SIGN_INVALID_INDEX, v));
                        }
                    }
                    a.index = v;
                    i += 2;
                } else if ("--sort-signer-infos".equals(tok)) {
                    String v = value(args, i, tok);
                    if (!SORT_CRITERIA.contains(v)) {
                        throw new ArgsException(Messages.get(MsgKey.SIGN_INVALID_SORT, v));
                    }
                    a.sortSignerInfos = v;
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
                    if (a.inputFile != null) {
                        throw new ArgsException(Messages.get(MsgKey.CLI_EXTRA_POSITIONAL_ARG, tok));
                    }
                    a.inputFile = tok;
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
