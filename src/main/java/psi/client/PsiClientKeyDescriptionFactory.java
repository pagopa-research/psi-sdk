package psi.client;

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

    public static PsiClientKeyDescription createEcBsClientKeyDescription(String ecServerPublicQ) {
        if (ecServerPublicQ == null) {
            throw new PsiClientException("The field ecServerPublicQ should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null, ecServerPublicQ);
    }

    public static PsiClientKeyDescription createEcDhClientKeyDescription(String ecClientPrivateD) {
        if (ecClientPrivateD == null) {
            throw new PsiClientException("The field ecClientPrivateD should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(ecClientPrivateD, null);
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

    public static PsiClientKeyDescription createEcBsClientKeyDescription(ECPoint ecServerPublicQ) {
        if (ecServerPublicQ == null) {
            throw new PsiClientException("The field ecServerPublicQ should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null,
                CustomTypeConverter.convertECPointToString(ecServerPublicQ));
    }

    public static PsiClientKeyDescription createEcDhClientKeyDescription(BigInteger ecClientPrivateD) {
        if (ecClientPrivateD == null) {
            throw new PsiClientException("The field ecClientPrivateD and should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecClientPrivateD),
                null);
    }

    public static PsiClientKeyDescription createGenericPsiClientKeyDescription(String clientPrivateExponent, String serverPublicExponent, String modulus, String ecClientPrivateD, String ecServerPublicQ) {
        if (serverPublicExponent != null && ecServerPublicQ != null)
            throw new PsiClientException("Only one of serverPublicExponent or ecServerPublicQ should be not null");

        if (clientPrivateExponent != null && ecClientPrivateD != null)
            throw new PsiClientException("Only one of clientPrivateExponent or ecClientPrivateD should be not null");

        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateExponent(clientPrivateExponent);
        psiClientKeyDescription.setServerPublicExponent(serverPublicExponent);
        psiClientKeyDescription.setModulus(modulus);
        psiClientKeyDescription.setEcClientPrivateD(ecClientPrivateD);
        psiClientKeyDescription.setEcServerPublicQ(ecServerPublicQ);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientKeyDescription(String clientPrivateExponent, String serverPublicExponent, String modulus) {
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateExponent(clientPrivateExponent);
        psiClientKeyDescription.setServerPublicExponent(serverPublicExponent);
        psiClientKeyDescription.setModulus(modulus);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientEcKeyDescription(String ecClientPrivateD, String ecServerPublicQ){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setEcClientPrivateD(ecClientPrivateD);
        psiClientKeyDescription.setEcServerPublicQ(ecServerPublicQ);
        return psiClientKeyDescription;
    }
}
