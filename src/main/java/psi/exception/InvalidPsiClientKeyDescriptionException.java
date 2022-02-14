package psi.exception;

/**
 * This exception is thrown whenever the user is trying to generate a generic PsiClientKeyDescription, but the input
 * parameters are not compliant versus any of the available algorithms.
 */
public class InvalidPsiClientKeyDescriptionException extends Exception {

    public InvalidPsiClientKeyDescriptionException() {
        super("The provided input is not compliant respect any psiClientKeyDescription parameters combination");
    }
}
