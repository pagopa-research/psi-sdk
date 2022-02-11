package psi.exception;

/**
 * This is a generic unchecked exception that is thrown whenever an unexpected and not compliant condition occurs.
 */
public class CustomRuntimeException extends  RuntimeException{

    public CustomRuntimeException(String message) {
        super(message);
    }
}
