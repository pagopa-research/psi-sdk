package psi.server.model;

import java.math.BigInteger;
import java.time.Instant;

public class SessionPayload {

    private BigInteger serverPrivateKey;
    private BigInteger serverPublicKey;
    private BigInteger modulus;
    private Instant expiration;
    private String algorithm;
    private int keySize;
    private String datatypeId;
    private String datatypeDescription;

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

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
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
        return "SessionPayload{" +
                "serverPrivateKey=" + serverPrivateKey +
                ", serverPublicKey=" + serverPublicKey +
                ", modulus=" + modulus +
                ", expiration=" + expiration +
                ", algorithm='" + algorithm + '\'' +
                ", keySize=" + keySize +
                ", datatypeId='" + datatypeId + '\'' +
                ", datatypeDescription='" + datatypeDescription + '\'' +
                '}';
    }
}
