package psi;

import psi.model.PsiKeyDescription;

import java.io.Serializable;
import java.util.Objects;

/**
 * Contains the variables used by the server to perform encryption operations.
 * The set of variables is a superset of the ones required by each psi implementation. In particular:
 * <ul>
 *   <li>DH uses modulus, generator and privateExponent (the modulus and the generator are sent to the client)</li>
 *   <li>BS uses modulus, privateExponent and publicExponent (the modulus and the publicExponent are sent to the client)</li>
 *   <li>ECDH uses ecPrivateD</li>
 *   <li>ECBS uses ecPrivateD and ecPublicQ (the ecPublicQ is sent to the client)</li>
 * </ul>
 */
public class PsiServerKeyDescription implements PsiKeyDescription, Serializable {

    private static final long serialVersionUID = 1L;

    private String privateExponent;
    private String publicExponent;
    private String modulus;
    private String generator;

    private String ecPrivateD;
    private String ecPublicQ;

    protected PsiServerKeyDescription() {
    }

    public String getPrivateExponent() {
        return privateExponent;
    }

    void setPrivateExponent(String privateExponent) {
        this.privateExponent = privateExponent;
    }

    public String getPublicExponent() {
        return publicExponent;
    }

    void setPublicExponent(String publicExponent) {
        this.publicExponent = publicExponent;
    }

    public String getModulus() {
        return modulus;
    }

    void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getEcPrivateD() {
        return ecPrivateD;
    }

    void setEcPrivateD(String ecPrivateD) {
        this.ecPrivateD = ecPrivateD;
    }

    public String getEcPublicQ() {
        return ecPublicQ;
    }

    void setEcPublicQ(String ecPublicQ) {
        this.ecPublicQ = ecPublicQ;
    }

    public String getGenerator() {
        return generator;
    }

    public void setGenerator(String generator) {
        this.generator = generator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PsiServerKeyDescription that = (PsiServerKeyDescription) o;
        return Objects.equals(privateExponent, that.privateExponent) && Objects.equals(publicExponent, that.publicExponent) && Objects.equals(modulus, that.modulus) && Objects.equals(generator, that.generator) && Objects.equals(ecPrivateD, that.ecPrivateD) && Objects.equals(ecPublicQ, that.ecPublicQ);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateExponent, publicExponent, modulus, generator, ecPrivateD, ecPublicQ);
    }

    @Override
    public String toString() {
        return "PsiServerKeyDescription{" +
                "privateExponent='" + privateExponent + '\'' +
                ", publicExponent='" + publicExponent + '\'' +
                ", modulus='" + modulus + '\'' +
                ", generator='" + generator + '\'' +
                ", ecPrivateD='" + ecPrivateD + '\'' +
                ", ecPublicQ='" + ecPublicQ + '\'' +
                '}';
    }
}
