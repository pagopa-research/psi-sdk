package psi.dto;

import java.util.Objects;

public class PsiAlgorithmParameterDTO {

    private PsiAlgorithmDTO algorithm;

    private Integer keySize;

    public PsiAlgorithmParameterDTO() {
    }

    public PsiAlgorithmParameterDTO(PsiAlgorithmDTO algorithm, Integer keySize) {
        this.algorithm = algorithm;
        this.keySize = keySize;
    }

    public PsiAlgorithmDTO getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(PsiAlgorithmDTO algorithm) {
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
        PsiAlgorithmParameterDTO that = (PsiAlgorithmParameterDTO) o;
        return algorithm == that.algorithm &&
                Objects.equals(keySize, that.keySize);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, keySize);
    }

    @Override
    public String toString() {
        return "SessionParameterDTO{" +
                "algorithm='" + algorithm + '\'' +
                ", keySize=" + keySize +
                '}';
    }
}
