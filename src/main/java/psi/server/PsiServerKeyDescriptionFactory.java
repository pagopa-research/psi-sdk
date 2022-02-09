package psi.server;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.CustomTypeConverter;
import psi.exception.PsiClientException;

import java.math.BigInteger;

public class PsiServerKeyDescriptionFactory {

    private PsiServerKeyDescriptionFactory() {
    }

    public static PsiServerKeyDescription createBsServerKeyDescription(String privateExponent, String publicExponent, String modulus) {
        if (privateExponent == null || publicExponent == null || modulus == null) {
            throw new PsiClientException("PrivateExponent, publicExponent and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(privateExponent, publicExponent, modulus, null);
    }

    public static PsiServerKeyDescription createDhServerKeyDescription(String privateExponent, String modulus, String generator) {
        if (privateExponent == null || modulus == null) {
            throw new PsiClientException("PrivateExponent, modulus and generator should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(privateExponent, null, modulus, generator);
    }

    public static PsiServerKeyDescription createEcBsServerKeyDescription(String ecPrivateKey, String ecPublicKey, String ecSpecName) {
        if (ecPrivateKey == null || ecPublicKey == null || ecSpecName == null) {
            throw new PsiClientException("PrivateKey, publicKey and modulus should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(ecPrivateKey, ecPublicKey, ecSpecName);
    }

    public static PsiServerKeyDescription createEcDhServerKeyDescription(String ecPrivateKey, String ecSpecName) {
        if (ecPrivateKey == null || ecSpecName == null) {
            throw new PsiClientException("PrivateKey and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerEcKeyDescription(ecPrivateKey, null, ecSpecName);
    }

    public static PsiServerKeyDescription createBsServerKeyDescription(BigInteger privateExponent, BigInteger publicExponent, BigInteger modulus) {
        if (privateExponent == null || publicExponent == null || modulus == null) {
            throw new PsiClientException("PrivateExponent, publicExponent and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(privateExponent),
                CustomTypeConverter.convertBigIntegerToString(publicExponent),
                CustomTypeConverter.convertBigIntegerToString(modulus),
                null);
    }

    public static PsiServerKeyDescription createDhServerKeyDescription(BigInteger privateExponent, BigInteger modulus, BigInteger generator) {
        if (privateExponent == null || modulus == null || generator == null) {
            throw new PsiClientException("PrivateExponent, modulus and generator should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(privateExponent),
                null,
                CustomTypeConverter.convertBigIntegerToString(modulus),
                CustomTypeConverter.convertBigIntegerToString(generator));
    }

    public static PsiServerKeyDescription createEcBsServerKeyDescription(BigInteger ecPrivateKey, ECPoint ecPublicKey, ECParameterSpec ecSpec) {
        if (ecPrivateKey == null || ecPublicKey == null || ecSpec == null) {
            throw new PsiClientException("EcPrivateKey, ecPublicKey and ecSpec should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateKey),
                CustomTypeConverter.convertECPointToString(ecPublicKey),
                CustomTypeConverter.convertECParameterSpecToString(ecSpec));
    }

    public static PsiServerKeyDescription createEcDhServerKeyDescription(BigInteger ecPrivateKey, ECParameterSpec ecSpec){
        if(ecPrivateKey == null ||  ecSpec == null){
            throw new PsiClientException("EcPrivateKey and ecSpec should not be null when creating a PsiServerKeyDescription for the ECDH algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateKey),
                null,
                CustomTypeConverter.convertECParameterSpecToString(ecSpec));
    }

    private static PsiServerKeyDescription createServerKeyDescription(String privateExponent, String publicExponent, String modulus, String generator) {
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setPrivateExponent(privateExponent);
        psiServerKeyDescription.setPublicExponent(publicExponent);
        psiServerKeyDescription.setModulus(modulus);
        psiServerKeyDescription.setGenerator(generator);
        return psiServerKeyDescription;
    }

    private static PsiServerKeyDescription createServerEcKeyDescription(String ecPrivateKey, String ecPublicKey, String ecSpecName){
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setEcPrivateKey(ecPrivateKey);
        psiServerKeyDescription.setEcPublicKey(ecPublicKey);
        psiServerKeyDescription.setEcSpecName(ecSpecName);
        return psiServerKeyDescription;
    }
}
