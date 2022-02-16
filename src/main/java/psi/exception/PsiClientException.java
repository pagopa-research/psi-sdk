package psi.exception;

/**
 * This exception is thrown whenever an unexpected and not compliant condition occurs when creating the client objects
 * or performing client operations, e.g., missing or incompatible keys.
 */
public class PsiClientException extends RuntimeException {
    public PsiClientException(String s) {
        super(s);
    }
}
