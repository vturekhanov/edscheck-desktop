package kz.edscheck.errors;

public class OperationalException extends EdsCheckException {
    public OperationalException(String message) {
        super(message);
    }

    public OperationalException(String message, Throwable cause) {
        super(message, cause);
    }
}
