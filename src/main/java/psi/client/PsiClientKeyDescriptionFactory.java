package psi.client;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.exception.PsiClientException;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;

public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {
    }

    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicKey, String modulus) {
        if (serverPublicKey == null || modulus == null || serverPublicKey.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null, serverPublicKey, modulus);
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(String clientPrivateKey, String modulus) {
        if (clientPrivateKey == null || modulus == null || clientPrivateKey.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("Both clientPrivateKey and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(clientPrivateKey, null, modulus);
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

    public static PsiClientKeyDescription createBsClientKeyDescription(BigInteger serverPublicKey, BigInteger modulus) {
        if (serverPublicKey == null || modulus == null) {
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null,
                CustomTypeConverter.convertBigIntegerToString(serverPublicKey),
                CustomTypeConverter.convertBigIntegerToString(modulus));
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(BigInteger clientPrivateKey, BigInteger modulus) {
        if (clientPrivateKey == null || modulus == null) {
            throw new PsiClientException("Both clientPrivateKey and mo dulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(clientPrivateKey),
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

    public static PsiClientKeyDescription createGenericPsiClientKeyDescription(String clientPrivateKey, String serverPublicKey, String modulus, String ecClientPrivateKey, String ecServerPublicKey, String ecSpecName) {
        if(serverPublicKey != null && ecServerPublicKey != null)
            throw new PsiClientException("Only one of serverPublicKey or ecServerPublicKey should be not null");

        if(clientPrivateKey != null && ecClientPrivateKey != null)
            throw new PsiClientException("Only one of clientPrivateKey or ecClientPrivateKey should be not null");

        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateKey(clientPrivateKey);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
        psiClientKeyDescription.setModulus(modulus);
        psiClientKeyDescription.setEcClientPrivateKey(ecClientPrivateKey);
        psiClientKeyDescription.setEcServerPublicKey(ecServerPublicKey);
        psiClientKeyDescription.setEcSpecName(ecSpecName);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientKeyDescription(String clientPrivateKey, String serverPublicKey, String modulus){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateKey(clientPrivateKey);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
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
