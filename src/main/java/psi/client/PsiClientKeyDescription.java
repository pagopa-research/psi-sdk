package psi.client;

import psi.model.PsiKeyDescription;

import java.io.Serializable;
import java.util.Objects;

public class PsiClientKeyDescription implements PsiKeyDescription, Serializable {

    private static final long serialVersionUID = 1L;

    private String clientPrivateKey;
    private String serverPublicKey;
    private String modulus;
    private String generator;

    private String ecClientPrivateKey;
    private String ecServerPublicKey;

    protected PsiClientKeyDescription() {
    }

    public String getClientPrivateKey() {
        return clientPrivateKey;
    }

    void setClientPrivateKey(String clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public String getServerPublicKey() {
        return serverPublicKey;
    }

    void setServerPublicKey(String serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public String getModulus() {
        return modulus;
    }

    void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getEcClientPrivateKey() {
        return ecClientPrivateKey;
    }

    void setEcClientPrivateKey(String ecClientPrivateKey) {
        this.ecClientPrivateKey = ecClientPrivateKey;
    }

    public String getEcServerPublicKey() {
        return ecServerPublicKey;
    }

    void setEcServerPublicKey(String ecServerPublicKey) {
        this.ecServerPublicKey = ecServerPublicKey;
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
        PsiClientKeyDescription that = (PsiClientKeyDescription) o;
        return Objects.equals(clientPrivateKey, that.clientPrivateKey) && Objects.equals(serverPublicKey, that.serverPublicKey) && Objects.equals(modulus, that.modulus) && Objects.equals(generator, that.generator) && Objects.equals(ecClientPrivateKey, that.ecClientPrivateKey) && Objects.equals(ecServerPublicKey, that.ecServerPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientPrivateKey, serverPublicKey, modulus, generator, ecClientPrivateKey, ecServerPublicKey);
    }

    @Override
    public String toString() {
        return "PsiClientKeyDescription{" +
                "clientPrivateKey='" + clientPrivateKey + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                ", generator='" + generator + '\'' +
                ", ecClientPrivateKey='" + ecClientPrivateKey + '\'' +
                ", ecServerPublicKey='" + ecServerPublicKey + '\'' +
                '}';
    }
}
