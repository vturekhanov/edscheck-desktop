package kz.edscheck.xml;

import java.util.Set;

final class XmlAlgorithms {

    static final Set<String> CANONICALIZATION = Set.of(
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

    static final Set<String> SIGNATURE_METHOD = Set.of(

        "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",

        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512");

    static final Set<String> DIGEST_METHOD = Set.of(
        "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512");

    static final Set<String> TRANSFORM = Set.of(
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        "http://www.w3.org/2002/06/xmldsig-filter2");

    private XmlAlgorithms() {
    }
}
