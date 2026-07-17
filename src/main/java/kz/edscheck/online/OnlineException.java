package kz.edscheck.online;


public class OnlineException extends RuntimeException {
    public OnlineException(String message) {
        super(message);
    }

    public OnlineException(String message, Throwable cause) {
        super(message, cause);
    }
}
