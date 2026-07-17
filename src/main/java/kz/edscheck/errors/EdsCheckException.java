package kz.edscheck.errors;


public class EdsCheckException extends RuntimeException {
    public EdsCheckException(String message) {
        super(message);
    }

    public EdsCheckException(String message, Throwable cause) {
        super(message, cause);
    }
}
