package psi.exception;

/**
 * A generic unchecked exception that is thrown whenever an unexpected and or/not compliant condition occurs.
 */
public class CustomRuntimeException extends  RuntimeException{

    public CustomRuntimeException(String message) {
        super(message);
    }
}
