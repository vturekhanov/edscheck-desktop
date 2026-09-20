package kz.edscheck.pades;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;

public final class PadesDss {
    private PadesDss() {
    }

    public static PadesDssMaterial extract(byte[] raw) {
        try (PDDocument doc = Loader.loadPDF(raw)) {
            COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
            COSDictionary dss = catalog.getCOSDictionary(COSName.getPDFName("DSS"));
            if (dss == null) {
                return null;
            }
            return new PadesDssMaterial(
                streamBytes(dss, "Certs"), streamBytes(dss, "CRLs"), streamBytes(dss, "OCSPs"));
        } catch (IOException e) {
            return null;
        }
    }

    private static List<byte[]> streamBytes(COSDictionary dss, String key) {
        COSArray array = dss.getCOSArray(COSName.getPDFName(key));
        if (array == null) {
            return List.of();
        }
        List<byte[]> out = new ArrayList<>(array.size());
        for (int i = 0; i < array.size(); i++) {
            COSBase base = array.getObject(i);
            if (!(base instanceof COSStream stream)) {
                continue;
            }
            try (var in = stream.createInputStream()) {
                out.add(in.readAllBytes());
            } catch (IOException e) {

            }
        }
        return out;
    }
}
