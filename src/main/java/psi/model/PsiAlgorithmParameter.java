package psi.model;

import java.util.Objects;

public class PsiAlgorithmParameter {

    private PsiAlgorithm algorithm;

    private Integer keySize;

    public PsiAlgorithmParameter() {
    }

    public PsiAlgorithmParameter(PsiAlgorithm algorithm, Integer keySize) {
        this.algorithm = algorithm;
        this.keySize = keySize;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PsiAlgorithmParameter that = (PsiAlgorithmParameter) o;
        return algorithm == that.algorithm &&
                Objects.equals(keySize, that.keySize);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, keySize);
    }

    @Override
    public String toString() {
        return "PsiAlgorithmParameter{" +
                "algorithm=" + algorithm +
                ", keySize=" + keySize +
                '}';
    }
}