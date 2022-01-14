package psi.client.algorithm.bs.model;

import psi.client.model.PsiClientKeyDescription;

public class BsClientKeyDescription implements PsiClientKeyDescription {

    private Long keyId;
    private String serverPublicKey;
    private String modulus;

    public BsClientKeyDescription() {
    }

    public BsClientKeyDescription(Long keyId, String serverPublicKey, String modulus) {
        this.keyId = keyId;
        this.serverPublicKey = serverPublicKey;
        this.modulus = modulus;
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

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }

    @Override
    public String toString() {
        return "BsClientKeyDescription{" +
                "keyId=" + keyId +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                '}';
    }
}
