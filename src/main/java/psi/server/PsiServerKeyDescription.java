package psi.server;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.model.PsiKeyDescription;

import java.math.BigInteger;

public class PsiServerKeyDescription implements PsiKeyDescription {

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;

    private BigInteger ecPrivateKey;
    private ECPoint ecPublicKey;
    private ECParameterSpec ecSpec;

    protected PsiServerKeyDescription() {
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger getEcPrivateKey() {
        return ecPrivateKey;
    }

    void setEcPrivateKey(BigInteger ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
    }

    public ECPoint getEcPublicKey() {
        return ecPublicKey;
    }

    void setEcPublicKey(ECPoint ecPublicKey) {
        this.ecPublicKey = ecPublicKey;
    }

    public ECParameterSpec getEcSpec() {
        return ecSpec;
    }

    void setEcSpec(ECParameterSpec ecSpec) {
        this.ecSpec = ecSpec;
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
