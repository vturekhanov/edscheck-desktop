package kz.edscheck.ddcard;

import java.util.List;

import kz.edscheck.domain.DocumentSource;


public record DdcardContent(
        DocumentSource document,
        String documentName,
        List<byte[]> signatures,
        List<String> signatureNames) {
}
