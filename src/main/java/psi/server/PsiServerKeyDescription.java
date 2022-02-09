package psi.server;

import psi.model.PsiKeyDescription;

import java.io.Serializable;
import java.util.Objects;

public class PsiServerKeyDescription implements PsiKeyDescription, Serializable {

    private static final long serialVersionUID = 1L;

    private String privateKey;
    private String publicKey;
    private String modulus;
    private String generator;

    private String ecPrivateKey;
    private String ecPublicKey;

    protected PsiServerKeyDescription() {
    }

    public String getPrivateKey() {
        return privateKey;
    }

    void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
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
        return Objects.equals(privateKey, that.privateKey) && Objects.equals(publicKey, that.publicKey) && Objects.equals(modulus, that.modulus) && Objects.equals(generator, that.generator) && Objects.equals(ecPrivateKey, that.ecPrivateKey) && Objects.equals(ecPublicKey, that.ecPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKey, publicKey, modulus, generator, ecPrivateKey, ecPublicKey);
    }

    @Override
    public String toString() {
        return "PsiServerKeyDescription{" +
                "privateKey='" + privateKey + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                ", generator='" + generator + '\'' +
                ", ecPrivateKey='" + ecPrivateKey + '\'' +
                ", ecPublicKey='" + ecPublicKey + '\'' +
                '}';
    }
}
