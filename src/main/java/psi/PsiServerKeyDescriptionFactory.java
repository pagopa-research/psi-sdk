package psi;

import org.bouncycastle.math.ec.ECPoint;
import psi.exception.PsiClientException;

import java.math.BigInteger;

public class PsiServerKeyDescriptionFactory {

    private PsiServerKeyDescriptionFactory() {}

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

    public static PsiServerKeyDescription createEcBsServerKeyDescription(String ecPrivateD, String ecPublicQ){
        if(ecPrivateD == null || ecPublicQ == null){
            throw new PsiClientException("EcPrivateD and ecPublicQ should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(ecPrivateD, ecPublicQ);
    }

    public static PsiServerKeyDescription createEcDhServerKeyDescription(String ecPrivateD){
        if(ecPrivateD == null){
            throw new PsiClientException("The field ecPrivateD should not be null when creating a PsiServerKeyDescription for the ECDH algorithm");
        }
        return createServerEcKeyDescription(ecPrivateD, null);
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

    public static PsiServerKeyDescription createEcBsServerKeyDescription(BigInteger ecPrivateD, ECPoint ecPublicQ){
        if(ecPrivateD == null || ecPublicQ == null){
            throw new PsiClientException("EcPrivateD and ecPublicQ should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateD),
                CustomTypeConverter.convertECPointToString(ecPublicQ));
    }

    public static PsiServerKeyDescription createEcDhServerKeyDescription(BigInteger ecPrivateD){
        if(ecPrivateD == null){
            throw new PsiClientException("The field ecPrivateD should not be null when creating a PsiServerKeyDescription for the ECDH algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateD),
                null);
    }

    private static PsiServerKeyDescription createServerKeyDescription(String privateExponent, String publicExponent, String modulus, String generator) {
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setPrivateExponent(privateExponent);
        psiServerKeyDescription.setPublicExponent(publicExponent);
        psiServerKeyDescription.setModulus(modulus);
        psiServerKeyDescription.setGenerator(generator);
        return psiServerKeyDescription;
    }

    private static PsiServerKeyDescription createServerEcKeyDescription(String ecPrivateD, String ecPublicQ){
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setEcPrivateD(ecPrivateD);
        psiServerKeyDescription.setEcPublicQ(ecPublicQ);
        return psiServerKeyDescription;
    }
}
