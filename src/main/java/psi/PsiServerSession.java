package psi;

import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;

public class PsiServerSession {

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
