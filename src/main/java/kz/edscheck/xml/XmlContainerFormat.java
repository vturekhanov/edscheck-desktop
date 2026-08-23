package kz.edscheck.xml;

enum XmlContainerFormat {
    XMLDSIG("xmldsig"),
    XADES("xades"),
    XMLDSIG_DETACHED("xmldsig-detached"),
    XADES_DETACHED("xades-detached"),
    XMLESF("xmlesf");

    private final String value;

    XmlContainerFormat(String value) {
        this.value = value;
    }

    String value() {
        return value;
    }
}
