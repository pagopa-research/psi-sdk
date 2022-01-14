package psi.dto;

public class PsiAlgorithmParameterDTO {

    private String algorithm;

    private Integer keySize;

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }

    @Override
    public String toString() {
        return "SessionParameterDTO{" +
                "algorithm='" + algorithm + '\'' +
                ", keySize=" + keySize +
                '}';
    }
}
