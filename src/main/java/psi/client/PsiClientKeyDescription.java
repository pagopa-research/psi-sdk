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
        return Objects.equals(clientPrivateExponent, that.clientPrivateExponent) && Objects.equals(serverPublicExponent, that.serverPublicExponent) && Objects.equals(modulus, that.modulus) && Objects.equals(ecClientPrivateD, that.ecClientPrivateD) && Objects.equals(ecServerPublicQ, that.ecServerPublicQ);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientPrivateExponent, serverPublicExponent, modulus, ecClientPrivateD, ecServerPublicQ);
    }

    @Override
    public String toString() {
        return "PsiClientKeyDescription{" +
                "clientPrivateExponent='" + clientPrivateExponent + '\'' +
                ", serverPublicExponent='" + serverPublicExponent + '\'' +
                ", modulus='" + modulus + '\'' +
                ", ecClientPrivateD='" + ecClientPrivateD + '\'' +
                ", ecServerPublicQ='" + ecServerPublicQ + '\'' +
                '}';
    }
}
