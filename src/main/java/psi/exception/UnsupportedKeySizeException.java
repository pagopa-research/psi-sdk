package psi.exception;

import psi.model.PsiAlgorithm;


/**
 * This exception is called whenever the server attempts to init a session with an unsupported key size,
 * or when a client attemps to load a session associated to an unsupported key size.
 */
public class UnsupportedKeySizeException extends Exception {

    public UnsupportedKeySizeException(PsiAlgorithm psiAlgorithm, int keySize) {
        super("Key size " + keySize + " is not supported by the algorithm " + psiAlgorithm.toString());
    }
}
