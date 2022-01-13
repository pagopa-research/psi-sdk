package psi.model;

import java.math.BigInteger;

public class BsServerSession extends ServerSession {

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
