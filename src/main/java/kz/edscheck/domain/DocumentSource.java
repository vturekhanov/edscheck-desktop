package kz.edscheck.domain;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;


public interface DocumentSource {
    InputStream open() throws IOException;

    default byte[] readAllBytes() throws IOException {
        try (InputStream in = open()) {
            return in.readAllBytes();
        }
    }

    static DocumentSource ofFile(Path path) {
        return () -> Files.newInputStream(path);
    }

    static DocumentSource ofBytes(byte[] bytes) {
        return () -> new ByteArrayInputStream(bytes);
    }

    
    static DocumentSource ofStdin() {
        return () -> System.in;
    }
}
