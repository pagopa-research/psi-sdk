package psi;

import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;

import java.io.Serializable;

/**
 * Object created during the initialization of a psi session which contains all the information required to load a
 * PsiServer instance.
 */
public class PsiServerSession implements Serializable {

    private static final long serialVersionUID = 1L;

    private PsiAlgorithmParameter psiAlgorithmParameter;
    private Boolean cacheEnabled;
    private PsiServerKeyDescription psiServerKeyDescription;

    PsiServerSession() {
    }

    public PsiServerSession(PsiAlgorithmParameter psiAlgorithmParameter) {
        this.psiAlgorithmParameter = psiAlgorithmParameter;
    }

    public PsiServerSession(PsiAlgorithmParameter psiAlgorithmParameter, Boolean cacheEnabled, PsiServerKeyDescription psiServerKeyDescription) {
        this.psiAlgorithmParameter = psiAlgorithmParameter;
        this.cacheEnabled = cacheEnabled;
        this.psiServerKeyDescription = psiServerKeyDescription;
    }

    public PsiServerSession(PsiAlgorithm algorithm, Integer keySize, Boolean cacheEnabled, PsiServerKeyDescription psiServerKeyDescription) {
        this.psiAlgorithmParameter = new PsiAlgorithmParameter();
        this.psiAlgorithmParameter.setAlgorithm(algorithm);
        this.psiAlgorithmParameter.setKeySize(keySize);
        this.cacheEnabled = cacheEnabled;
        this.psiServerKeyDescription = psiServerKeyDescription;
    }

    public PsiAlgorithmParameter getPsiAlgorithmParameter() {
        return psiAlgorithmParameter;
    }

    public void setPsiAlgorithmParameter(PsiAlgorithmParameter psiAlgorithmParameter) {
        this.psiAlgorithmParameter = psiAlgorithmParameter;
    }

    public Boolean getCacheEnabled() {
        return cacheEnabled;
    }

    void setCacheEnabled(Boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }

    public PsiServerKeyDescription getPsiServerKeyDescription() {
        return psiServerKeyDescription;
    }

    void setPsiServerKeyDescription(PsiServerKeyDescription psiServerKeyDescription) {
        this.psiServerKeyDescription = psiServerKeyDescription;
    }

    @Override
    public String toString() {
        return "PsiServerSession{" +
                "psiAlgorithmParameter=" + psiAlgorithmParameter +
                ", cacheEnabled=" + cacheEnabled +
                ", psiServerKeyDescription=" + psiServerKeyDescription +
                '}';
    }
}
