package psi.client;

import psi.model.PsiKeyDescription;

import java.io.Serializable;
import java.util.Objects;

public class PsiClientKeyDescription implements PsiKeyDescription, Serializable {

    private static final long serialVersionUID = 1L;

    private String clientPrivateExponent;
    private String serverPublicExponent;
    private String modulus;

    private String ecClientPrivateKey;
    private String ecServerPublicKey;
    private String ecSpecName;

    protected PsiClientKeyDescription() {
    }

    public String getClientPrivateExponent() {
        return clientPrivateExponent;
    }

    void setClientPrivateExponent(String clientPrivateExponent) {
        this.clientPrivateExponent = clientPrivateExponent;
    }

    public String getServerPublicExponent() {
        return serverPublicExponent;
    }

    void setServerPublicExponent(String serverPublicExponent) {
        this.serverPublicExponent = serverPublicExponent;
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

    public String getEcSpecName() {
        return ecSpecName;
    }

    void setEcSpecName(String ecSpecName) {
        this.ecSpecName = ecSpecName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PsiClientKeyDescription that = (PsiClientKeyDescription) o;
        return Objects.equals(clientPrivateExponent, that.clientPrivateExponent) && Objects.equals(serverPublicExponent, that.serverPublicExponent) && Objects.equals(modulus, that.modulus) && Objects.equals(ecClientPrivateKey, that.ecClientPrivateKey) && Objects.equals(ecServerPublicKey, that.ecServerPublicKey) && Objects.equals(ecSpecName, that.ecSpecName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientPrivateExponent, serverPublicExponent, modulus, ecClientPrivateKey, ecServerPublicKey, ecSpecName);
    }

    @Override
    public String toString() {
        return "PsiClientKeyDescription{" +
                "clientPrivateExponent='" + clientPrivateExponent + '\'' +
                ", serverPublicExponent='" + serverPublicExponent + '\'' +
                ", modulus='" + modulus + '\'' +
                ", ecClientPrivateKey='" + ecClientPrivateKey + '\'' +
                ", ecServerPublicKey='" + ecServerPublicKey + '\'' +
                ", ecSpecName='" + ecSpecName + '\'' +
                '}';
    }
}
