package psi.client;

import psi.exception.PsiClientException;

public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {}

    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicKey, String modulus){
        if(serverPublicKey == null || modulus == null){
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null, serverPublicKey, modulus);
    }

    public static PsiClientKeyDescription createDhClientKeyDescription(String clientPrivateKey, String modulus){
        if(clientPrivateKey == null || modulus == null){
            throw new PsiClientException("Both clientPrivateKey and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(clientPrivateKey, null, modulus);
    }

    private static PsiClientKeyDescription createClientKeyDescription(String clientPrivateKey, String serverPublicKey, String modulus){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateKey(clientPrivateKey);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
        psiClientKeyDescription.setModulus(modulus);
        return psiClientKeyDescription;
    }
}
