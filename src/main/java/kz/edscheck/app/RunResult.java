package kz.edscheck.app;

import kz.edscheck.domain.SignedContainer;
import kz.edscheck.domain.VerificationRequest;

public record RunResult(SignedContainer container, VerificationRequest request) {
}
