package psi.client;

import org.bouncycastle.math.ec.ECPoint;
import psi.CustomTypeConverter;
import psi.exception.PsiClientException;

import java.math.BigInteger;

public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {
    }

    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicKey, String modulus) {
        if (serverPublicKey == null || modulus == null || serverPublicKey.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null, serverPublicKey, modulus, null);
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(String clientPrivateKey, String modulus, String generator) {
        if (clientPrivateKey == null || modulus == null || generator == null || clientPrivateKey.isEmpty() || modulus.isEmpty() || generator.isEmpty()) {
            throw new PsiClientException("The fields clientPrivateKey, modulus and generator should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(clientPrivateKey, null, modulus, generator);
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

    public static PsiClientKeyDescription createBsClientKeyDescription(BigInteger serverPublicKey, BigInteger modulus) {
        if (serverPublicKey == null || modulus == null) {
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null,
                CustomTypeConverter.convertBigIntegerToString(serverPublicKey),
                CustomTypeConverter.convertBigIntegerToString(modulus),
                null);
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(BigInteger clientPrivateKey, BigInteger modulus, BigInteger generator) {
        if (clientPrivateKey == null || modulus == null || generator == null) {
            throw new PsiClientException("The fields clientPrivateKey, modulus and generator should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(clientPrivateKey),
                null,
                CustomTypeConverter.convertBigIntegerToString(modulus),
                CustomTypeConverter.convertBigIntegerToString(generator));
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

    public static PsiClientKeyDescription createGenericPsiClientKeyDescription(String clientPrivateKey, String serverPublicKey, String modulus, String generator, String ecClientPrivateD, String ecServerPublicQ) {
        if (serverPublicKey != null && ecServerPublicQ != null)
            throw new PsiClientException("Only one of serverPublicKey or ecServerPublicQ should be not null");

        if (clientPrivateKey != null && ecClientPrivateD != null)
            throw new PsiClientException("Only one of clientPrivateKey or ecClientPrivateD should be not null");

        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateKey(clientPrivateKey);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
        psiClientKeyDescription.setModulus(modulus);
        psiClientKeyDescription.setGenerator(generator);
        psiClientKeyDescription.setEcClientPrivateD(ecClientPrivateD);
        psiClientKeyDescription.setEcServerPublicQ(ecServerPublicQ);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientKeyDescription(String clientPrivateKey, String serverPublicKey, String modulus, String generator) {
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateKey(clientPrivateKey);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
        psiClientKeyDescription.setModulus(modulus);
        psiClientKeyDescription.setGenerator(generator);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientEcKeyDescription(String ecClientPrivateD, String ecServerPublicQ){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setEcClientPrivateD(ecClientPrivateD);
        psiClientKeyDescription.setEcServerPublicQ(ecServerPublicQ);
        return psiClientKeyDescription;
    }
}
