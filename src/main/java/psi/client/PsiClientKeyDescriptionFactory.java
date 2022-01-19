package psi.client;

import psi.exception.PsiClientException;

public class PsiClientKeyDescriptionFactory {

    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicKey, String modulus){
        return createBsClientKeyDescription(serverPublicKey, modulus, null);
    }

    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicKey, String modulus, Long keyId){
        if(serverPublicKey == null || modulus == null){
            throw new PsiClientException("Both serverPublicKey and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        if(keyId != null)
            psiClientKeyDescription.setKeyId(keyId);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
        psiClientKeyDescription.setModulus(modulus);
        return psiClientKeyDescription;
    }
}
