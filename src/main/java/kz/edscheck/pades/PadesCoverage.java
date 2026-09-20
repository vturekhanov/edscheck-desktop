package kz.edscheck.pades;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class PadesCoverage {
    private PadesCoverage() {
    }

    public static boolean covers(PadesSignatureObject mark, PadesSignatureObject target) {
        int targetEnd = target.coveredEnd();
        int markGapStart = mark.gapStart();
        return targetEnd >= 0 && markGapStart >= 0 && targetEnd <= markGapStart;
    }

    public static List<PadesSignatureObject> coveringChain(
            PadesSignatureObject target, List<PadesSignatureObject> allObjects) {
        List<PadesSignatureObject> chain = new ArrayList<>();
        for (PadesSignatureObject object : allObjects) {
            if (object.isArchiveTimestamp() && covers(object, target)) {
                chain.add(object);
            }
        }
        chain.sort(Comparator.comparingInt(PadesSignatureObject::gapStart));
        return chain;
    }

    public static List<PadesSignatureObject> unassignedArchiveTimestamps(List<PadesSignatureObject> allObjects) {
        List<PadesSignatureObject> unassigned = new ArrayList<>();
        for (PadesSignatureObject object : allObjects) {
            if (!object.isArchiveTimestamp()) {
                continue;
            }
            boolean coversAny = false;
            for (PadesSignatureObject candidate : allObjects) {
                if (candidate.isSignature() && covers(object, candidate)) {
                    coversAny = true;
                    break;
                }
            }
            if (!coversAny) {
                unassigned.add(object);
            }
        }
        return unassigned;
    }
}
