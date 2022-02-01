package psi.server;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
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

    public static PsiServerKeyDescription createEcbsServerKeyDescription(String ecPrivateKey, String ecPublicKey, String ecSpecName){
        if(ecPrivateKey == null || ecPublicKey == null || ecSpecName == null){
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        ECParameterSpec ecSpec = CustomTypeConverter.convertStringToECParameterSpec(ecSpecName);
        return createServerEcKeyDescription(
                CustomTypeConverter.convertStringToBigInteger(ecPrivateKey),
                CustomTypeConverter.convertStringToECPoint(ecSpec.getCurve(), ecPublicKey),
                ecSpec);
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

    public static PsiServerKeyDescription createEcbsServerKeyDescription(BigInteger ecPrivateKey, ECPoint ecPublicKey, ECParameterSpec ecSpec){
        if(ecPrivateKey == null || ecPublicKey == null || ecSpec == null){
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerEcKeyDescription(ecPrivateKey,ecPublicKey,ecSpec);
    }

    private static PsiServerKeyDescription createServerKeyDescription(BigInteger privateKey, BigInteger publicKey, BigInteger modulus){
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setPrivateKey(privateKey);
        psiServerKeyDescription.setPublicKey(publicKey);
        psiServerKeyDescription.setModulus(modulus);
        return psiServerKeyDescription;
    }

    private static PsiServerKeyDescription createServerEcKeyDescription(BigInteger ecPrivateKey, ECPoint ecPublicKey, ECParameterSpec ecSpec){
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setEcPrivateKey(ecPrivateKey);
        psiServerKeyDescription.setEcPublicKey(ecPublicKey);
        psiServerKeyDescription.setEcSpec(ecSpec);
        return psiServerKeyDescription;
    }
}
