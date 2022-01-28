package psi.server;

import psi.exception.PsiClientException;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;

public class PsiServerKeyDescriptionFactory {

    private PsiServerKeyDescriptionFactory() {}

    public static PsiServerKeyDescription createBsServerKeyDescription(String privateKey, String publicKey, String modulus){
        if(privateKey == null || publicKey == null || modulus == null){
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertStringToBigInteger(privateKey),
                CustomTypeConverter.convertStringToBigInteger(publicKey),
                CustomTypeConverter.convertStringToBigInteger(modulus));
    }

    public static PsiServerKeyDescription createDhServerKeyDescription(String privateKey, String modulus){
        if(privateKey == null || modulus == null){
            throw new PsiClientException("PrivateKey and modulus should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertStringToBigInteger(privateKey),
                null,
                CustomTypeConverter.convertStringToBigInteger(modulus));
    }

    public static PsiServerKeyDescription createBsServerKeyDescription(BigInteger privateKey, BigInteger publicKey, BigInteger modulus){
        if(privateKey == null || publicKey == null || modulus == null){
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(privateKey, publicKey, modulus);
    }

    public static PsiServerKeyDescription createDhServerKeyDescription(BigInteger privateKey, BigInteger modulus){
        if(privateKey == null || modulus == null){
            throw new PsiClientException("PrivateKey and modulus should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(privateKey, null, modulus);
    }

    private static PsiServerKeyDescription createServerKeyDescription(BigInteger privateKey, BigInteger publicKey, BigInteger modulus){
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setPrivateKey(privateKey);
        psiServerKeyDescription.setPublicKey(publicKey);
        psiServerKeyDescription.setModulus(modulus);
        return psiServerKeyDescription;
    }
}
