package kz.edscheck.ddcard;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.common.PDNameTreeNode;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import kz.edscheck.domain.DocumentSource;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class Ddcard {
    private static final byte[] PDF_MAGIC = "%PDF-".getBytes(StandardCharsets.US_ASCII);

    private static final Pattern NUM_SUFFIX = Pattern.compile("^(.*?)(\\d+)$");

    private Ddcard() {
    }

    public static String detectInputFormat(byte[] raw) {
        if (raw.length >= PDF_MAGIC.length) {
            boolean match = true;
            for (int i = 0; i < PDF_MAGIC.length; i++) {
                if (raw[i] != PDF_MAGIC[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return "ddcard";
            }
        }
        return "cms";
    }

    public static boolean looksLikeDdcard(DocumentSource source) throws IOException {
        byte[] prefix = new byte[PDF_MAGIC.length];
        try (InputStream in = source.open()) {
            int n = in.readNBytes(prefix, 0, prefix.length);
            return n == prefix.length && "ddcard".equals(detectInputFormat(prefix));
        }
    }

    public static DdcardContent parseDdcard(byte[] raw) {
        if (!"ddcard".equals(detectInputFormat(raw))) {
            throw new ContainerException(Messages.get(MsgKey.DDCARD_NOT_PDF));
        }

        String documentKey;
        String documentName;
        List<byte[]> signatures = new ArrayList<>();
        List<String> signatureNames = new ArrayList<>();
        try (PDDocument doc = Loader.loadPDF(raw)) {
            List<Entry> entries = embeddedFilesInOrder(doc);
            if (entries.isEmpty()) {
                throw new ContainerException(Messages.get(MsgKey.DDCARD_NO_EMBEDDED_FILES));
            }
            if (entries.size() < 2) {
                throw new ContainerException(Messages.get(MsgKey.DDCARD_NO_SIGNATURES));
            }

            Entry documentEntry = entries.get(0);
            documentKey = documentEntry.key();
            documentName = documentEntry.displayName();
            for (int i = 1; i < entries.size(); i++) {
                Entry e = entries.get(i);
                signatures.add(embeddedBytes(e.spec()));
                signatureNames.add(e.displayName());
            }
        } catch (ContainerException e) {
            throw e;
        } catch (Exception e) {
            throw new ContainerException(Messages.get(MsgKey.DDCARD_PARSE_FAILED, e.getMessage()), e);
        }

        return new DdcardContent(
            documentSourceForKey(raw, documentKey), documentName, signatures, signatureNames);
    }

    public static byte[] reconstructAttached(byte[] cmsBytes, byte[] document) {
        try {
            Object asn1 = new ASN1InputStream(cmsBytes).readObject();
            ContentInfo outer = ContentInfo.getInstance(asn1);
            SignedData signedData = SignedData.getInstance(outer.getContent());
            ContentInfo encap = signedData.getEncapContentInfo();
            if (encap.getContent() != null) {
                return cmsBytes; 
            }
            ContentInfo newEncap = new ContentInfo(encap.getContentType(), new DEROctetString(document));
            SignedData newSignedData = new SignedData(
                signedData.getDigestAlgorithms(), newEncap, signedData.getCertificates(),
                signedData.getCRLs(), signedData.getSignerInfos());
            ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);

            return newOuter.getEncoded(ASN1Encoding.DL);
        } catch (ContainerException e) {
            throw e;
        } catch (Exception e) {
            throw new ContainerException(Messages.get(MsgKey.DDCARD_RECONSTRUCT_FAILED, e.getMessage()), e);
        }
    }

    private record Entry(String key, String displayName, PDComplexFileSpecification spec) {
    }

    private static List<Entry> embeddedFilesInOrder(PDDocument doc) throws Exception {
        PDDocumentCatalog catalog = doc.getDocumentCatalog();
        PDDocumentNameDictionary names = catalog.getNames();
        if (names == null) {
            return List.of();
        }
        PDEmbeddedFilesNameTreeNode embeddedFiles = names.getEmbeddedFiles();
        if (embeddedFiles == null) {
            return List.of();
        }
        List<Entry> collected = new ArrayList<>();
        walkNameTree(embeddedFiles, collected);
        return normalizeOrder(collected);
    }

    private static void walkNameTree(
            PDNameTreeNode<PDComplexFileSpecification> node, List<Entry> out) throws Exception {
        var names = node.getNames();
        if (names != null) {
            for (var e : names.entrySet()) {
                String key = e.getKey();
                PDComplexFileSpecification spec = e.getValue();
                out.add(new Entry(key, displayName(spec, key), spec));
            }
        }
        var kids = node.getKids();
        if (kids != null) {
            for (PDNameTreeNode<PDComplexFileSpecification> kid : kids) {
                walkNameTree(kid, out);
            }
        }
    }

    private static DocumentSource documentSourceForKey(byte[] raw, String key) {
        return () -> {
            PDDocument doc = Loader.loadPDF(raw);
            try {
                PDComplexFileSpecification spec = findByKey(doc, key);
                if (spec == null) {
                    throw new IOException(Messages.get(MsgKey.DDCARD_ATTACHMENT_NOT_FOUND, key));
                }
                PDEmbeddedFile ef = spec.getEmbeddedFile();
                if (ef == null) {
                    ef = spec.getEmbeddedFileUnicode();
                }
                if (ef == null) {
                    throw new IOException(Messages.get(MsgKey.DDCARD_ATTACHMENT_NO_EF_STREAM));
                }
                InputStream fileIn = ef.createInputStream();
                return new FilterInputStream(fileIn) {
                    @Override
                    public void close() throws IOException {
                        try {
                            super.close();
                        } finally {
                            doc.close();
                        }
                    }
                };
            } catch (Exception e) {
                doc.close();
                if (e instanceof IOException ioe) {
                    throw ioe;
                }
                throw new IOException(Messages.get(MsgKey.DDCARD_ATTACHMENT_OPEN_FAILED, key, e.getMessage()), e);
            }
        };
    }

    private static PDComplexFileSpecification findByKey(PDDocument doc, String key) throws Exception {
        PDDocumentCatalog catalog = doc.getDocumentCatalog();
        PDDocumentNameDictionary names = catalog.getNames();
        if (names == null) {
            return null;
        }
        PDEmbeddedFilesNameTreeNode embeddedFiles = names.getEmbeddedFiles();
        if (embeddedFiles == null) {
            return null;
        }
        return findByKey(embeddedFiles, key);
    }

    private static PDComplexFileSpecification findByKey(
            PDNameTreeNode<PDComplexFileSpecification> node, String key) throws Exception {
        var names = node.getNames();
        if (names != null) {
            PDComplexFileSpecification spec = names.get(key);
            if (spec != null) {
                return spec;
            }
        }
        var kids = node.getKids();
        if (kids != null) {
            for (PDNameTreeNode<PDComplexFileSpecification> kid : kids) {
                PDComplexFileSpecification found = findByKey(kid, key);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static byte[] embeddedBytes(PDComplexFileSpecification spec) throws Exception {
        PDEmbeddedFile ef = spec.getEmbeddedFile();
        if (ef == null) {
            ef = spec.getEmbeddedFileUnicode();
        }
        if (ef == null) {
            throw new ContainerException(Messages.get(MsgKey.DDCARD_ATTACHMENT_NO_EF_STREAM));
        }
        return ef.toByteArray();
    }

    private static String displayName(PDComplexFileSpecification spec, String fallback) {
        String name = spec.getFileUnicode();
        if (name == null) {
            name = spec.getFile();
        }
        return name != null ? name : fallback;
    }

    private static List<Entry> normalizeOrder(List<Entry> entries) {
        if (entries.size() < 2) {
            return entries;
        }
        List<Matcher> matchers = new ArrayList<>();
        for (Entry e : entries) {
            matchers.add(NUM_SUFFIX.matcher(e.key()));
        }
        boolean allMatch = true;
        String commonPrefix = null;
        boolean prefixConsistent = true;
        for (Matcher m : matchers) {
            if (!m.matches()) {
                allMatch = false;
                break;
            }
            String prefix = m.group(1);
            if (commonPrefix == null) {
                commonPrefix = prefix;
            } else if (!commonPrefix.equals(prefix)) {
                prefixConsistent = false;
            }
        }
        if (!allMatch || !prefixConsistent) {
            return entries;
        }
        List<Entry> sorted = new ArrayList<>(entries);
        sorted.sort(java.util.Comparator.comparingInt(Ddcard::numericSuffix));
        return sorted;
    }

    private static int numericSuffix(Entry e) {
        Matcher m = NUM_SUFFIX.matcher(e.key());
        m.matches();
        return Integer.parseInt(m.group(2));
    }
}
