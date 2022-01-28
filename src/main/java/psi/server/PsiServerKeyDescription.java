package psi.server;

import psi.model.PsiKeyDescription;

import java.math.BigInteger;

public class PsiServerKeyDescription implements PsiKeyDescription {

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;

    protected PsiServerKeyDescription() {
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    @Override
    public String toString() {
        return "PsiServerKeyDescription{" +
                "privateKey='" + privateKey + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                '}';
    }
}
