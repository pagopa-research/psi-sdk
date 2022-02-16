package psi.exception;

/**
 * This exception is thrown whenever an unexpected and not compliant condition occurs when loading the server objects
 * or performing server operations, e.g., missing psiCacheProvider implementation while it is enabled.
 */
public class PsiServerException extends RuntimeException {

    public PsiServerException(String s) {
        super(s);
    }
}

