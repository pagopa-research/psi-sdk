package psi.server;

import psi.model.PsiKeyDescription;

import java.io.Serializable;
import java.util.Objects;

public class PsiServerKeyDescription implements PsiKeyDescription, Serializable {

    private static final long serialVersionUID = 1L;

    private String privateExponent;
    private String publicExponent;
    private String modulus;
    private String generator;

    private String ecPrivateKey;
    private String ecPublicKey;
    private String ecSpecName;

    protected PsiServerKeyDescription() {
    }

    public String getPrivateExponent() {
        return privateExponent;
    }

    void setPrivateExponent(String privateExponent) {
        this.privateExponent = privateExponent;
    }

    public String getPublicExponent() {
        return publicExponent;
    }

    void setPublicExponent(String publicExponent) {
        this.publicExponent = publicExponent;
    }

    public String getModulus() {
        return modulus;
    }

    void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getEcPrivateKey() {
        return ecPrivateKey;
    }

    void setEcPrivateKey(String ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
    }

    public String getEcPublicKey() {
        return ecPublicKey;
    }

    void setEcPublicKey(String ecPublicKey) {
        this.ecPublicKey = ecPublicKey;
    }

    public String getEcSpecName() {
        return ecSpecName;
    }

    void setEcSpecName(String ecSpecName) {
        this.ecSpecName = ecSpecName;
    }

    public String getGenerator() {
        return generator;
    }

    public void setGenerator(String generator) {
        this.generator = generator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PsiServerKeyDescription that = (PsiServerKeyDescription) o;
        return Objects.equals(privateExponent, that.privateExponent) && Objects.equals(publicExponent, that.publicExponent) && Objects.equals(modulus, that.modulus) && Objects.equals(generator, that.generator) && Objects.equals(ecPrivateKey, that.ecPrivateKey) && Objects.equals(ecPublicKey, that.ecPublicKey) && Objects.equals(ecSpecName, that.ecSpecName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateExponent, publicExponent, modulus, generator, ecPrivateKey, ecPublicKey, ecSpecName);
    }

    @Override
    public String toString() {
        return "PsiServerKeyDescription{" +
                "privateExponent='" + privateExponent + '\'' +
                ", publicExponent='" + publicExponent + '\'' +
                ", modulus='" + modulus + '\'' +
                ", generator='" + generator + '\'' +
                ", ecPrivateKey='" + ecPrivateKey + '\'' +
                ", ecPublicKey='" + ecPublicKey + '\'' +
                ", ecSpecName='" + ecSpecName + '\'' +
                '}';
    }
}
