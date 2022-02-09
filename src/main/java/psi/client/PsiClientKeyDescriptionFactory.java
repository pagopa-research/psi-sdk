package psi.client;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.CustomTypeConverter;
import psi.exception.PsiClientException;

import java.math.BigInteger;

public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {
    }

    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicExponent, String modulus) {
        if (serverPublicExponent == null || modulus == null || serverPublicExponent.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("Both serverPublicExponent and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null, serverPublicExponent, modulus);
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(String clientPrivateExponent, String modulus) {
        if (clientPrivateExponent == null || modulus == null || clientPrivateExponent.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("The fields clientPrivateExponent and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(clientPrivateExponent, null, modulus);
    }

    public static PsiClientKeyDescription createEcBsClientKeyDescription(String ecServerPublicKey, String ecSpecName) {
        if (ecServerPublicKey == null || ecSpecName == null) {
            throw new PsiClientException("Both ecServerPublicKey and ecSpecName should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null, ecServerPublicKey, ecSpecName);
    }

    public static PsiClientKeyDescription createEcDhClientKeyDescription(String ecClientPrivateKey, String ecSpecName) {
        if (ecClientPrivateKey == null || ecSpecName == null) {
            throw new PsiClientException("Both ecClientPrivateKey and ecSpecName should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(ecClientPrivateKey, null, ecSpecName);
    }

    public static PsiClientKeyDescription createBsClientKeyDescription(BigInteger serverPublicExponent, BigInteger modulus) {
        if (serverPublicExponent == null || modulus == null) {
            throw new PsiClientException("Both serverPublicExponent and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null,
                CustomTypeConverter.convertBigIntegerToString(serverPublicExponent),
                CustomTypeConverter.convertBigIntegerToString(modulus));
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(BigInteger clientPrivateExponent, BigInteger modulus) {
        if (clientPrivateExponent == null || modulus == null) {
            throw new PsiClientException("The fields clientPrivateExponent and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(clientPrivateExponent),
                null,
                CustomTypeConverter.convertBigIntegerToString(modulus));
    }

    public static PsiClientKeyDescription createEcBsClientKeyDescription(ECPoint ecServerPublicKey, ECParameterSpec ecSpec) {
        if (ecServerPublicKey == null || ecSpec == null) {
            throw new PsiClientException("Both ecServerPublicKey and ecSpec should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null,
                CustomTypeConverter.convertECPointToString(ecServerPublicKey),
                CustomTypeConverter.convertECParameterSpecToString(ecSpec));
    }

    public static PsiClientKeyDescription createEcDhClientKeyDescription(BigInteger ecClientPrivateKey, ECParameterSpec ecSpec) {
        if (ecClientPrivateKey == null || ecSpec == null) {
            throw new PsiClientException("Both ecClientPrivateKey and ecSpec should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecClientPrivateKey),
                null,
                CustomTypeConverter.convertECParameterSpecToString(ecSpec));
    }

    public static PsiClientKeyDescription createGenericPsiClientKeyDescription(String clientPrivateExponent, String serverPublicExponent, String modulus, String ecClientPrivateKey, String ecServerPublicKey, String ecSpecName) {
        if (serverPublicExponent != null && ecServerPublicKey != null)
            throw new PsiClientException("Only one of serverPublicExponent or ecServerPublicKey should be not null");

        if (clientPrivateExponent != null && ecClientPrivateKey != null)
            throw new PsiClientException("Only one of clientPrivateExponent or ecClientPrivateKey should be not null");

        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateExponent(clientPrivateExponent);
        psiClientKeyDescription.setServerPublicExponent(serverPublicExponent);
        psiClientKeyDescription.setModulus(modulus);
        psiClientKeyDescription.setEcClientPrivateKey(ecClientPrivateKey);
        psiClientKeyDescription.setEcServerPublicKey(ecServerPublicKey);
        psiClientKeyDescription.setEcSpecName(ecSpecName);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientKeyDescription(String clientPrivateExponent, String serverPublicExponent, String modulus) {
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateExponent(clientPrivateExponent);
        psiClientKeyDescription.setServerPublicExponent(serverPublicExponent);
        psiClientKeyDescription.setModulus(modulus);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientEcKeyDescription(String ecClientPrivateKey, String ecServerPublicKey, String ecSpecName){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setEcClientPrivateKey(ecClientPrivateKey);
        psiClientKeyDescription.setEcServerPublicKey(ecServerPublicKey);
        psiClientKeyDescription.setEcSpecName(ecSpecName);
        return psiClientKeyDescription;
    }
}
