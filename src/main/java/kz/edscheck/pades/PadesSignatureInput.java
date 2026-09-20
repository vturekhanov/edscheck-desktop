package kz.edscheck.pades;

import java.util.List;

public record PadesSignatureInput(
        int index,
        PadesSignatureObject object,
        List<PadesSignatureObject> allObjects,
        byte[] fileBytes,
        PadesDssMaterial dss) {

    public PadesSignatureInput {
        allObjects = allObjects == null ? List.of() : List.copyOf(allObjects);
    }
}
