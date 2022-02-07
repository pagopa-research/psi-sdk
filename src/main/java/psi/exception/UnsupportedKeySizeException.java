package psi.exception;

import psi.model.PsiAlgorithm;

public class UnsupportedKeySizeException extends Exception {

    public UnsupportedKeySizeException(PsiAlgorithm psiAlgorithm, int keySize) {
        super("Key size " + keySize + " is not supported by the algorithm " + psiAlgorithm.toString());
    }
}
