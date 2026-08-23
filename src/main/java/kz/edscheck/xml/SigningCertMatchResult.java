package kz.edscheck.xml;

record SigningCertMatchResult(String digestAlgorithm, boolean matched, String errorDetail) {
}
