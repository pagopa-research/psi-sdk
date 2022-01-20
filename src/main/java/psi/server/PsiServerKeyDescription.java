package psi.server;

import psi.model.PsiKeyDescription;

public class PsiServerKeyDescription implements PsiKeyDescription {

    private String privateKey;
    private String publicKey;
    private String modulus;

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


    @Override
    public String toString() {
        return "BsKeyDescription{" +
                "privateKey='" + privateKey + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                '}';
    }

}
