package psi.client;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.exception.PsiClientException;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;

public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {}

    //TODO: ECBS

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

    public static PsiClientKeyDescription createEcbsClientKeyDescription(String ecServerPublicKey, String ecSpecName){
        if(ecServerPublicKey == null || ecSpecName == null){
            throw new PsiClientException("Both ecServerPublicKey and ecSpecName should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        ECParameterSpec ecSpec = CustomTypeConverter.convertStringToECParameterSpec(ecSpecName);
        return createClientEcKeyDescription(
                null,
                CustomTypeConverter.convertStringToECPoint(ecSpec.getCurve(), ecServerPublicKey),
                ecSpec);
    }

    public static PsiClientKeyDescription createEcdhClientKeyDescription(String ecClientPrivateKey, String ecSpecName){
        if(ecClientPrivateKey == null || ecSpecName == null){
            throw new PsiClientException("Both ecClientPrivateKey and ecSpecName should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(
                CustomTypeConverter.convertStringToBigInteger(ecClientPrivateKey),
                null,
                CustomTypeConverter.convertStringToECParameterSpec(ecSpecName));
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

    public static PsiClientKeyDescription createEcbsClientKeyDescription(ECPoint ecServerPublicKey, ECParameterSpec ecSpec){
        if(ecServerPublicKey == null || ecSpec == null){
            throw new PsiClientException("Both ecServerPublicKey and ecSpec should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null, ecServerPublicKey, ecSpec);
    }

    public static PsiClientKeyDescription createEcdhClientKeyDescription(BigInteger ecClientPrivateKey, ECParameterSpec ecSpec){
        if(ecClientPrivateKey == null || ecSpec == null){
            throw new PsiClientException("Both ecClientPrivateKey and ecSpec should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(ecClientPrivateKey, null, ecSpec);
    }

    private static PsiClientKeyDescription createClientKeyDescription(BigInteger clientPrivateKey, BigInteger serverPublicKey, BigInteger modulus){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateKey(clientPrivateKey);
        psiClientKeyDescription.setServerPublicKey(serverPublicKey);
        psiClientKeyDescription.setModulus(modulus);
        return psiClientKeyDescription;
    }

    private static PsiClientKeyDescription createClientEcKeyDescription(BigInteger ecClientPrivateKey, ECPoint ecServerPublicKey, ECParameterSpec ecSpec){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setEcClientPrivateKey(ecClientPrivateKey);
        psiClientKeyDescription.setEcServerPublicKey(ecServerPublicKey);
        psiClientKeyDescription.setEcSpec(ecSpec);
        return psiClientKeyDescription;
    }
}
