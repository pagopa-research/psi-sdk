package psi.model;

import java.math.BigInteger;
import java.time.Instant;

public class ServerSessionPayload {

    private BigInteger serverPrivateKey;
    private BigInteger serverPublicKey;
    private BigInteger modulus;
    private Instant expiration;
    private String algorithm;
    private Integer keySize;
    private String datatypeId;
    private String datatypeDescription;
    private Long cacheKeyId;
    private boolean cacheEnabled;

    public BigInteger getServerPrivateKey() {
        return serverPrivateKey;
    }

    public void setServerPrivateKey(BigInteger serverPrivateKey) {
        this.serverPrivateKey = serverPrivateKey;
    }

    public BigInteger getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(BigInteger serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public Instant getExpiration() {
        return expiration;
    }

    public void setExpiration(Instant expiration) {
        this.expiration = expiration;
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

    public Long getCacheKeyId() {
        return cacheKeyId;
    }

    public void setCacheKeyId(Long cacheKeyId) {
        this.cacheKeyId = cacheKeyId;
    }

    public boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }

    @Override
    public String toString() {
        return "ServerSessionPayload{" +
                "serverPrivateKey=" + serverPrivateKey +
                ", serverPublicKey=" + serverPublicKey +
                ", modulus=" + modulus +
                ", expiration=" + expiration +
                ", algorithm='" + algorithm + '\'' +
                ", keySize=" + keySize +
                ", datatypeId='" + datatypeId + '\'' +
                ", datatypeDescription='" + datatypeDescription + '\'' +
                ", cacheKeyId=" + cacheKeyId +
                ", cacheEnabled=" + cacheEnabled +
                '}';
    }
}
