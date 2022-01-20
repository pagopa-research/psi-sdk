package psi.client;

import psi.model.PsiKeyDescription;

public class PsiClientKeyDescription implements PsiKeyDescription {

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

    @Override
    public String toString() {
        return "PsiClientKeyDescription{" +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                '}';
    }
}
