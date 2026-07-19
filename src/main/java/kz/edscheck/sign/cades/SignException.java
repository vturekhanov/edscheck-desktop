package kz.edscheck.sign.cades;

public class SignException extends RuntimeException {
    public SignException(String message) {
        super(message);
    }

    public SignException(String message, Throwable cause) {
        super(message, cause);
    }
}
