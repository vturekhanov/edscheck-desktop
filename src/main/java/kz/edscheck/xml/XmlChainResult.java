package kz.edscheck.xml;

import java.util.List;

import kz.edscheck.provider.CaRevocationFact;
import kz.edscheck.provider.StageOutcome;

record XmlChainResult(StageOutcome outcome, List<CaRevocationFact> intermediateCaRevocations) {
}
