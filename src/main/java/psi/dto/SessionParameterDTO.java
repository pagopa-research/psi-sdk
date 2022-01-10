package psi.dto;

public class SessionParameterDTO {

    private String algorithm;

    private Integer keySize;

    private String datatypeId;

    private String datatypeDescription;

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

    public String getDatatypeId() {
        return datatypeId;
    }

    public void setDatatypeId(String datatypeId) {
        this.datatypeId = datatypeId;
    }

    public String getDatatypeDescription() {
        return datatypeDescription;
    }

    public void setDatatypeDescription(String datatypeDescription) {
        this.datatypeDescription = datatypeDescription;
    }

    @Override
    public String toString() {
        return "SessionParameterDTO{" +
                "algorithm='" + algorithm + '\'' +
                ", keySize=" + keySize +
                ", datatypeId='" + datatypeId + '\'' +
                ", datatypeDescription='" + datatypeDescription + '\'' +
                '}';
    }
}
