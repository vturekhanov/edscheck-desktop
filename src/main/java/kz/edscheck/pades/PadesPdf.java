package kz.edscheck.pades;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class PadesPdf {
    private PadesPdf() {
    }

    public static boolean looksLikePades(byte[] raw) {
        try {
            return !extract(raw).isEmpty();
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static List<PadesSignatureObject> extract(byte[] raw) {
        try (PDDocument doc = Loader.loadPDF(raw)) {
            PDAcroForm form = doc.getDocumentCatalog().getAcroForm(null);
            if (form == null) {
                throw new ContainerException(Messages.get(MsgKey.PADES_NO_ACROFORM_FIELDS));
            }
            List<PadesSignatureObject> objects = new ArrayList<>();
            for (PDField field : form.getFieldTree()) {
                if (!(field instanceof PDSignatureField sigField)) {
                    continue;
                }
                PDSignature signature = sigField.getSignature();
                if (signature == null) {
                    continue; 
                }
                objects.add(parseSignatureDict(signature, fieldName(field), raw));
            }
            if (objects.isEmpty()) {
                throw new ContainerException(Messages.get(MsgKey.PADES_NO_ACROFORM_FIELDS));
            }
            return objects;
        } catch (IOException e) {
            throw new ContainerException(Messages.get(MsgKey.PADES_PARSE_FAILED, e.getMessage()), e);
        }
    }

    private static String fieldName(PDField field) {
        String name = field.getFullyQualifiedName();
        return name != null ? name : "";
    }

    private static PadesSignatureObject parseSignatureDict(PDSignature signature, String fieldName, byte[] raw) {
        COSDictionary dict = signature.getCOSObject();
        String type = dict.getNameAsString(COSName.TYPE);
        byte[] contents = signature.getContents();
        int[] byteRange = signature.getByteRange();
        validateHygiene(byteRange, contents, raw);
        return new PadesSignatureObject(
            fieldName,
            type != null ? type : PadesSignatureObject.TYPE_SIGNATURE,
            signature.getSubFilter(),
            contents,
            byteRange,
            dict.getString(COSName.M));
    }

    private static void validateHygiene(int[] byteRange, byte[] contents, byte[] raw) {
        if (byteRange.length != 4) {
            throw new ContainerException(Messages.get(MsgKey.PADES_BYTE_RANGE_MALFORMED));
        }
        for (int value : byteRange) {
            if (value < 0) {
                throw new ContainerException(Messages.get(MsgKey.PADES_BYTE_RANGE_MALFORMED));
            }
        }
        if (byteRange[0] != 0 || byteRange[1] <= 0 || byteRange[3] <= 0 || byteRange[2] < byteRange[1]) {
            throw new ContainerException(Messages.get(MsgKey.PADES_BYTE_RANGE_MALFORMED));
        }
        if ((long) byteRange[2] + byteRange[3] > raw.length) {
            throw new ContainerException(Messages.get(MsgKey.PADES_BYTE_RANGE_MALFORMED));
        }
        if (contents == null) {
            throw new ContainerException(Messages.get(MsgKey.PADES_CONTENTS_GAP_MISMATCH));
        }
        StringBuilder expected = new StringBuilder(2 + contents.length * 2);
        expected.append('<');
        for (byte b : contents) {
            expected.append(String.format("%02X", b));
        }
        expected.append('>');
        int gapStart = byteRange[1];
        int gapEnd = byteRange[2];
        if (gapEnd - gapStart != expected.length()) {
            throw new ContainerException(Messages.get(MsgKey.PADES_CONTENTS_GAP_MISMATCH));
        }
        String actual = new String(raw, gapStart, gapEnd - gapStart, StandardCharsets.ISO_8859_1);
        if (!actual.toUpperCase(Locale.ROOT).equals(expected.toString())) {
            throw new ContainerException(Messages.get(MsgKey.PADES_CONTENTS_GAP_MISMATCH));
        }
    }
}
