package psi.client;

import psi.model.PsiKeyDescription;

import java.io.Serializable;
import java.util.Objects;

public class PsiClientKeyDescription implements PsiKeyDescription, Serializable {

    private static final long serialVersionUID = 1L;

    private String clientPrivateExponent;
    private String serverPublicExponent;
    private String modulus;

    private String ecClientPrivateD;
    private String ecServerPublicQ;

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

    public String getEcClientPrivateD() {
        return ecClientPrivateD;
    }

    void setEcClientPrivateD(String ecClientPrivateD) {
        this.ecClientPrivateD = ecClientPrivateD;
    }

    public String getEcServerPublicQ() {
        return ecServerPublicQ;
    }

    void setEcServerPublicQ(String ecServerPublicQ) {
        this.ecServerPublicQ = ecServerPublicQ;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PsiClientKeyDescription that = (PsiClientKeyDescription) o;
        return Objects.equals(clientPrivateKey, that.clientPrivateKey) && Objects.equals(serverPublicKey, that.serverPublicKey) && Objects.equals(modulus, that.modulus) && Objects.equals(generator, that.generator) && Objects.equals(ecClientPrivateKey, that.ecClientPrivateKey) && Objects.equals(ecServerPublicKey, that.ecServerPublicKey) && Objects.equals(ecSpecName, that.ecSpecName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientPrivateKey, serverPublicKey, modulus, generator, ecClientPrivateKey, ecServerPublicKey, ecSpecName);
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
                ", ecSpecName='" + ecSpecName + '\'' +
                '}';
    }
}
