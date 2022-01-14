package psi.server.model;

public abstract class ServerSession {

    private Long keyId;
    private String algorithm;
    private Integer keySize;
    private Boolean cacheEnabled;

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }

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

    public Boolean getCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(Boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }

    @Override
    public String toString() {
        return "ServerSession{" +
                "keyId=" + keyId +
                ", algorithm='" + algorithm + '\'' +
                ", keySize=" + keySize +
                ", cacheEnabled=" + cacheEnabled +
                '}';
    }
}
