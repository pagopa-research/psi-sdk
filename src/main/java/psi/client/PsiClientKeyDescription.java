package psi.client;

import psi.model.PsiKeyDescription;

import java.math.BigInteger;

public class PsiClientKeyDescription implements PsiKeyDescription {

    private BigInteger clientPrivateKey;
    private BigInteger serverPublicKey;
    private BigInteger modulus;

    protected PsiClientKeyDescription() {
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

    public BigInteger getClientPrivateKey() {
        return clientPrivateKey;
    }

    public void setClientPrivateKey(BigInteger clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    @Override
    public String toString() {
        return "PsiClientKeyDescription{" +
                "serverPublicKey='" + serverPublicKey + '\'' +
                ", clientPrivateKey='" + clientPrivateKey + '\'' +
                ", modulus='" + modulus + '\'' +
                '}';
    }
}
