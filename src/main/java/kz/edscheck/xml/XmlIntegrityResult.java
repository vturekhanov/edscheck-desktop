package kz.edscheck.xml;

import java.util.List;

record XmlIntegrityResult(IntegrityOutcome outcome, List<XmlReferenceResult> references, String errorDetail) {
}
