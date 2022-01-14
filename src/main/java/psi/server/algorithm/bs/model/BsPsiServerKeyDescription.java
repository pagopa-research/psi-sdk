package psi.server.algorithm.bs.model;

import psi.server.model.PsiServerKeyDescription;

public class BsPsiServerKeyDescription implements PsiServerKeyDescription {

    private String privateKey;
    private String publicKey;
    private String modulus;
    private Long keyId;

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

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }

    @Override
    public String toString() {
        return "BsKeyDescription{" +
                "privateKey='" + privateKey + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                ", keyId=" + keyId +
                '}';
    }
}
