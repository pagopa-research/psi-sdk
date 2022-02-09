package psi.server;

import org.bouncycastle.math.ec.ECPoint;
import psi.CustomTypeConverter;
import psi.exception.PsiClientException;

import java.math.BigInteger;

public class PsiServerKeyDescriptionFactory {

    private PsiServerKeyDescriptionFactory() {}

    public static PsiServerKeyDescription createBsServerKeyDescription(String privateKey, String publicKey, String modulus){
        if(privateKey == null || publicKey == null || modulus == null){
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(privateKey, publicKey, modulus, null);
    }

    public static PsiServerKeyDescription createDhServerKeyDescription(String privateKey, String modulus, String generator) {
        if (privateKey == null || modulus == null) {
            throw new PsiClientException("PrivateKey and modulus should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(privateKey, null, modulus, generator);
    }

    public static PsiServerKeyDescription createEcBsServerKeyDescription(String ecPrivateKey, String ecPublicKey){
        if(ecPrivateKey == null || ecPublicKey == null){
            throw new PsiClientException("PrivateKey and publicKey should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(ecPrivateKey, ecPublicKey);
    }

    public static PsiServerKeyDescription createEcDhServerKeyDescription(String ecPrivateKey){
        if(ecPrivateKey == null){
            throw new PsiClientException("The field PrivateKey should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerEcKeyDescription(ecPrivateKey, null);
    }

    public static PsiServerKeyDescription createBsServerKeyDescription(BigInteger privateKey, BigInteger publicKey, BigInteger modulus){
        if(privateKey == null || publicKey == null || modulus == null){
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(privateKey),
                CustomTypeConverter.convertBigIntegerToString(publicKey),
                CustomTypeConverter.convertBigIntegerToString(modulus),
                null);
    }

    public static PsiServerKeyDescription createDhServerKeyDescription(BigInteger privateKey, BigInteger modulus, BigInteger generator) {
        if (privateKey == null || modulus == null || generator == null) {
            throw new PsiClientException("PrivateKey, modulus and generator should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(privateKey),
                null,
                CustomTypeConverter.convertBigIntegerToString(modulus),
                CustomTypeConverter.convertBigIntegerToString(generator));
    }

    public static PsiServerKeyDescription createEcBsServerKeyDescription(BigInteger ecPrivateKey, ECPoint ecPublicKey){
        if(ecPrivateKey == null || ecPublicKey == null){
            throw new PsiClientException("EcPrivateKey and ecPublicKey should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateKey),
                CustomTypeConverter.convertECPointToString(ecPublicKey));
    }

    public static PsiServerKeyDescription createEcDhServerKeyDescription(BigInteger ecPrivateKey){
        if(ecPrivateKey == null){
            throw new PsiClientException("The field EcPrivateKey should not be null when creating a PsiServerKeyDescription for the ECDH algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateKey),
                null);
    }

    private static PsiServerKeyDescription createServerKeyDescription(String privateKey, String publicKey, String modulus, String generator) {
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setPrivateKey(privateKey);
        psiServerKeyDescription.setPublicKey(publicKey);
        psiServerKeyDescription.setModulus(modulus);
        psiServerKeyDescription.setGenerator(generator);
        return psiServerKeyDescription;
    }

    private static PsiServerKeyDescription createServerEcKeyDescription(String ecPrivateKey, String ecPublicKey){
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setEcPrivateKey(ecPrivateKey);
        psiServerKeyDescription.setEcPublicKey(ecPublicKey);
        return psiServerKeyDescription;
    }
}
