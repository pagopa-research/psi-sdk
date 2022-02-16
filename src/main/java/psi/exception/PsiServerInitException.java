package psi.exception;

/**
 * This exception is thrown whenever some data required to initialize a server session is missing or not
 * compliant with respect to the sdk logic, e.g., missing keys.
 */
public class PsiServerInitException extends RuntimeException {
    public PsiServerInitException(String s) {
        super(s);
    }
}
