package psi.server;

import psi.model.PsiAlgorithm;

public class PsiServerSession {

    private PsiAlgorithm algorithm;
    private Integer keySize;
    private Boolean cacheEnabled;
    private PsiServerKeyDescription psiServerKeyDescription;

    public PsiServerSession() {
    }

    public PsiServerSession(PsiAlgorithm algorithm, Integer keySize, Boolean cacheEnabled, PsiServerKeyDescription psiServerKeyDescription) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.cacheEnabled = cacheEnabled;
        this.psiServerKeyDescription = psiServerKeyDescription;
    }

    public PsiAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(PsiAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }

    public Boolean getCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(Boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }

    public PsiServerKeyDescription getPsiServerKeyDescription() {
        return psiServerKeyDescription;
    }

    public void setPsiServerKeyDescription(PsiServerKeyDescription psiServerKeyDescription) {
        this.psiServerKeyDescription = psiServerKeyDescription;
    }

    @Override
    public String toString() {
        return "PsiServerSession{" +
                "algorithm='" + algorithm + '\'' +
                ", keySize=" + keySize +
                ", cacheEnabled=" + cacheEnabled +
                ", psiServerKeyDescription=" + psiServerKeyDescription +
                '}';
    }
}
