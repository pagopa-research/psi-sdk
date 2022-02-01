package psi.client;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.model.PsiKeyDescription;

import java.math.BigInteger;

public class PsiClientKeyDescription implements PsiKeyDescription {

    private BigInteger clientPrivateKey;
    private BigInteger serverPublicKey;
    private BigInteger modulus;

    private BigInteger ecClientPrivateKey;
    private ECPoint ecServerPublicKey;
    private ECParameterSpec ecSpec;

    protected PsiClientKeyDescription() {
    }

    public BigInteger getServerPublicKey() {
        return serverPublicKey;
    }

    void setServerPublicKey(BigInteger serverPublicKey) {
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

    void setClientPrivateKey(BigInteger clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public ECParameterSpec getEcSpec() {
        return ecSpec;
    }

    void setEcSpec(ECParameterSpec ecSpec) {
        this.ecSpec = ecSpec;
    }

    public ECPoint getEcServerPublicKey() {
        return ecServerPublicKey;
    }

    public void setEcServerPublicKey(ECPoint ecServerPublicKey) {
        this.ecServerPublicKey = ecServerPublicKey;
    }

    public BigInteger getEcClientPrivateKey() {
        return ecClientPrivateKey;
    }

    public void setEcClientPrivateKey(BigInteger ecClientPrivateKey) {
        this.ecClientPrivateKey = ecClientPrivateKey;
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
