package psi.client;

import psi.exception.PsiClientException;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;

public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {}

    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicKey, String modulus){
        if(serverPublicKey == null || modulus == null || serverPublicKey.isEmpty() || modulus.isEmpty()){
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(
                null,
                CustomTypeConverter.convertStringToBigInteger(serverPublicKey),
                CustomTypeConverter.convertStringToBigInteger(modulus));
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(String clientPrivateKey, String modulus){
        if(clientPrivateKey == null || modulus == null || clientPrivateKey.isEmpty() || modulus.isEmpty()){
            throw new PsiClientException("Both clientPrivateKey and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(
                CustomTypeConverter.convertStringToBigInteger(clientPrivateKey),
                null,
                CustomTypeConverter.convertStringToBigInteger(modulus));
    }

    public static PsiClientKeyDescription createBsClientKeyDescription(BigInteger serverPublicKey, BigInteger modulus){
        if(serverPublicKey == null || modulus == null){
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null, serverPublicKey, modulus);
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(BigInteger clientPrivateKey, BigInteger modulus){
        if(clientPrivateKey == null || modulus == null){
            throw new PsiClientException("Both clientPrivateKey and mo dulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(clientPrivateKey, null, modulus);
    }

    private static PsiClientKeyDescription createClientKeyDescription(BigInteger clientPrivateKey, BigInteger serverPublicKey, BigInteger modulus){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateKey(clientPrivateKey);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
        psiClientKeyDescription.setModulus(modulus);
        return psiClientKeyDescription;
    }
}
