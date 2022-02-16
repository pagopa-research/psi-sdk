package psi.exception;

/**
 * This exception is thrown whenever an external key is not provided by the user and the sdk is not able to generate
 * by itself a new one. This exception is unchecked as it is thrown in situations that are not expected to occur.
 */
public class KeyGenerationException extends RuntimeException {

    public KeyGenerationException(String message) {
        super(message);
    }
}
