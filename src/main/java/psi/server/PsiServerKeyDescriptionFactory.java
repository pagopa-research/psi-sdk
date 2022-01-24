package psi.server;

import psi.exception.PsiClientException;

public class PsiServerKeyDescriptionFactory {

    public static PsiServerKeyDescription createBsServerKeyDescription(String privateKey, String publicKey, String modulus){
        if(privateKey == null || publicKey == null || modulus == null){
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setPrivateKey(privateKey);
        psiServerKeyDescription.setPublicKey(publicKey);
        psiServerKeyDescription.setModulus(modulus);
        return psiServerKeyDescription;
    }
}
