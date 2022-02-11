package psi.exception;

/**
 * This exception is thrown whenever the information required to initialize a server session are missing or not
 * compliant respect to the sdk, e.g., missing keys.
 */
public class PsiServerInitException extends RuntimeException {
    public PsiServerInitException(String s) {
        super(s);
    }
}
