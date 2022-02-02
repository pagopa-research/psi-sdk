package psi.server;

import psi.model.PsiKeyDescription;

import java.io.Serializable;
import java.util.Objects;

public class PsiServerKeyDescription implements PsiKeyDescription, Serializable {

    private static final long serialVersionUID = 1L;

    private String privateKey;
    private String publicKey;
    private String modulus;

    private String ecPrivateKey;
    private String ecPublicKey;
    private String ecSpecName;

    protected PsiServerKeyDescription() {
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getModulus() {
        return modulus;
    }

    public void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getEcPrivateKey() {
        return ecPrivateKey;
    }

    public void setEcPrivateKey(String ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
    }

    public String getEcPublicKey() {
        return ecPublicKey;
    }

    public void setEcPublicKey(String ecPublicKey) {
        this.ecPublicKey = ecPublicKey;
    }

    public String getEcSpecName() {
        return ecSpecName;
    }

    public void setEcSpecName(String ecSpecName) {
        this.ecSpecName = ecSpecName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PsiServerKeyDescription that = (PsiServerKeyDescription) o;
        return Objects.equals(privateKey, that.privateKey) &&
                Objects.equals(publicKey, that.publicKey) &&
                Objects.equals(modulus, that.modulus) &&
                Objects.equals(ecPrivateKey, that.ecPrivateKey) &&
                Objects.equals(ecPublicKey, that.ecPublicKey) &&
                Objects.equals(ecSpecName, that.ecSpecName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKey, publicKey, modulus, ecPrivateKey, ecPublicKey, ecSpecName);
    }

    @Override
    public String toString() {
        return "PsiServerKeyDescription{" +
                "privateKey='" + privateKey + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                ", ecPrivateKey='" + ecPrivateKey + '\'' +
                ", ecPublicKey='" + ecPublicKey + '\'' +
                ", ecSpecName='" + ecSpecName + '\'' +
                '}';
    }
}
