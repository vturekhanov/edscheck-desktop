package kz.edscheck.xml;

import java.util.List;

record XmlReference(
        String id,
        String uri,
        String type,
        List<String> transforms,
        String digestMethod,
        byte[] digestValue) {
}
