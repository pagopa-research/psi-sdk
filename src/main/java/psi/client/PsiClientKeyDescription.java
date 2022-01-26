package psi.client;

import psi.model.PsiKeyDescription;

public class PsiClientKeyDescription implements PsiKeyDescription {

    private String clientPrivateKey;
    private String serverPublicKey;
    private String modulus;

    protected PsiClientKeyDescription() {
    }

    public String getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(String serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public String getModulus() {
        return modulus;
    }

    public void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getClientPrivateKey() {
        return clientPrivateKey;
    }

    public void setClientPrivateKey(String clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
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
