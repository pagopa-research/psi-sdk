package psi.exception;

/**
 * This exception is thrown whenever an external key is not provided by the user and the sdk is not able to generate
 * itself a new one. This exception extends the RuntimeException class since it includes a series of cases that are not
 * expected to occur, e.g., since previously checked.
 */
public class KeyGenerationException extends RuntimeException {

    public KeyGenerationException(String message) {
        super(message);
    }
}
