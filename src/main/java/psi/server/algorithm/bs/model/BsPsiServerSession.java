package psi.server.algorithm.bs.model;

import psi.server.model.PsiServerSession;

public class BsPsiServerSession extends PsiServerSession {

    private String serverPrivateKey;
    private String serverPublicKey;
    private String modulus;

    public String getServerPrivateKey() {
        return serverPrivateKey;
    }

    public void setServerPrivateKey(String serverPrivateKey) {
        this.serverPrivateKey = serverPrivateKey;
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
        return super.toString()+'\''+
                "BsServerSession{" +
                "serverPrivateKey='" + serverPrivateKey + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", modulus='" + modulus + '\'' +
                '}';
    }
}
