package kz.edscheck.errors;

public class ContainerException extends OperationalException {
    public ContainerException(String message) {
        super(message);
    }

    public ContainerException(String message, Throwable cause) {
        super(message, cause);
    }
}
